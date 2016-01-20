package main

import (
	"bytes"
	"compress/bzip2"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/inconshreveable/go-update"
	"github.com/kardianos/osext"
	"github.com/pangolinfq/autoupdate-server/server"
)

type pangolinUpdater struct {
	initialVersion string
	interval       time.Duration
	pubKey         *rsa.PublicKey
	url            string
	filePath       string

	httpClient *http.Client

	stopCh  chan bool
	queryCh chan chan string
}

func newUpdater(initialVersion string, interval time.Duration, pubKey *rsa.PublicKey, updateURL string, proxyURL *url.URL) *pangolinUpdater {
	filePath, _ := osext.Executable()
	var httpClient *http.Client
	if proxyURL == nil {
		httpClient = &http.Client{
			Timeout: time.Minute,
		}
	} else {
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) { return proxyURL, nil },
			},
			Timeout: time.Minute,
		}
	}
	return &pangolinUpdater{
		initialVersion: initialVersion,
		interval:       interval,
		pubKey:         pubKey,
		url:            updateURL,
		filePath:       filePath,

		httpClient: httpClient,

		stopCh:  make(chan bool, 10),
		queryCh: make(chan chan string),
	}
}

func (u *pangolinUpdater) check(version string) (*server.Result, bool) {
	checksum, e := u.checksum()
	if e != nil {
		return nil, false
	}
	param := server.Params{
		AppVersion: version,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Checksum:   checksum,
	}
	log.Printf("check-update param: %v", param)
	body, e := json.Marshal(&param)
	if e != nil {
		return nil, false
	}
	resp, e := u.httpClient.Post(u.url, "application/json", bytes.NewReader(body))
	if e != nil {
		log.Printf("fail to query check-update: %s", e)
		return nil, false
	}
	if resp.StatusCode == http.StatusNoContent {
		log.Printf("check-update return: %d", http.StatusNoContent)
		return nil, true
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("check-update return: %d", resp.StatusCode)
		return nil, false
	}
	defer resp.Body.Close()
	respBytes, e := ioutil.ReadAll(resp.Body)
	if e != nil {
		log.Printf("fail to read check-update response: %s", e)
		return nil, false
	}
	result := &server.Result{}
	if e = json.Unmarshal(respBytes, result); e != nil {
		log.Printf("fail to parse check-update response: %s", e)
		return nil, false
	}
	log.Printf("check-update response: %v", result)
	return result, true
}

func (u *pangolinUpdater) checksum() (string, error) {
	log.Printf("file path: %s", u.filePath)
	f, e := os.Open(u.filePath)
	defer f.Close()
	if e != nil {
		log.Printf("fail to open file: %s", e)
		return "", e
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		log.Printf("fail to read file: %s", e)
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (u *pangolinUpdater) options(result *server.Result) update.Options {
	opt := update.Options{
		TargetPath: u.filePath,
		PublicKey:  u.pubKey,
		Hash:       crypto.SHA256,
	}
	opt.Checksum, _ = hex.DecodeString(result.Checksum)
	opt.Signature, _ = hex.DecodeString(result.Signature)
	opt.Verifier = update.NewRSAVerifier()
	if result.PatchType == server.PATCHTYPE_BSDIFF {
		opt.Patcher = update.NewBSDiffPatcher()
	}
	return opt
}

func (u *pangolinUpdater) update(version string) (string, bool) {
	result, succ := u.check(version)
	if result == nil {
		return version, succ
	}
	var downloadURL string
	if result.PatchType == server.PATCHTYPE_NONE {
		downloadURL = result.URL
	} else {
		downloadURL = result.PatchURL
	}

	resp, e := u.httpClient.Get(downloadURL)
	if e != nil {
		log.Printf("fail to get patch: %v", e)
		return version, false
	}
	defer resp.Body.Close()

	var newFile io.Reader
	if result.PatchType == server.PATCHTYPE_NONE {
		newFile = bzip2.NewReader(resp.Body)
	} else {
		newFile = resp.Body
	}
	e = update.Apply(newFile, u.options(result))
	if e != nil {
		if re := update.RollbackError(e); re != nil {
			log.Printf("Failed to rollback from bad update: %v", re)
		}
		return version, false
	}
	return result.Version, true
}

func (u *pangolinUpdater) version() string {
	ret := make(chan string)
	u.queryCh <- ret
	return <-ret
}

func (u *pangolinUpdater) run() {
	log.Printf("start updater ...")
	curVersion := u.initialVersion
	timer := time.NewTimer(10 * time.Second)
	for {
		select {
		case <-u.stopCh:
			return
		case <-timer.C:
			newVersion, succ := u.update(curVersion)
			if newVersion != curVersion {
				log.Printf("version update [%s -> %s]", curVersion, newVersion)
			}
			curVersion = newVersion
			if !succ {
				timer = time.NewTimer(10 * time.Minute)
			} else {
				timer = time.NewTimer(u.interval)
			}
		case query := <-u.queryCh:
			query <- curVersion
		}
	}
}

func (u *pangolinUpdater) stop() {
	log.Printf("stop updater")
	u.stopCh <- true
}
