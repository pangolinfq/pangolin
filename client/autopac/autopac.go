package autopac

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/getlantern/filepersist"
	"github.com/getlantern/i18n"
	"github.com/getlantern/pac"
	"github.com/pangolinfq/pangolin/client/ui"
)

const (
	formatter = `function FindProxyForURL(url, host) {
			if (isPlainHostName(host) // including localhost
			|| shExpMatch(host, "*.local")) {
				return "DIRECT";
			}
			// only checks plain IP addresses to avoid leaking domain name
			if (/^[0-9.]+$/.test(host)) {
				if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
				isInNet(host, "172.16.0.0",  "255.240.0.0") ||
				isInNet(host, "192.168.0.0",  "255.255.0.0") ||
				isInNet(host, "127.0.0.0", "255.255.255.0")) {
					return "DIRECT";
				}
			}
			return "PROXY %s; DIRECT";
		}`
	pacPath = "/pangolin.pac"
)

var (
	isPACOn = int32(0)
	pacFile []byte
	pacURL  string
)

func genPAC(proxyURL string) []byte {
	if pacFile == nil {
		pacFile = []byte(fmt.Sprintf(formatter, proxyURL))
	}
	return pacFile
}

func PromptPrivilegeEscalation(icon []byte) error {
	var iconFile string
	if runtime.GOOS == "darwin" {
		iconFile = filepath.Join("/tmp", "escalatelantern.ico")
		err := filepersist.Save(iconFile, icon, 0644)
		if err != nil {
			return fmt.Errorf("Unable to persist icon to disk: %v", err)
		} else {
			log.Printf("Saved icon file to: %v", iconFile)
		}
	}
	err := pac.EnsureHelperToolPresent("pac-cmd", i18n.T("PAC_SETUP"), iconFile)
	if err != nil {
		return fmt.Errorf("Unable to set up pac setting tool: %s", err)
	}
	return nil
}

func EnablePAC(proxyURL string) {
	log.Printf("Setting pangolin as system proxy")
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(genPAC(proxyURL)); err != nil {
			log.Printf("Error writing response: %s", err)
		}
	}
	pacURL = ui.Handle(pacPath, http.HandlerFunc(handler))
	log.Printf("Serving PAC file at %v", pacURL)
	err := pac.On(pacURL)
	if err != nil {
		log.Printf("Unable to set pangolin as system proxy: %s", err)
	}
	atomic.StoreInt32(&isPACOn, 1)
}

func DisablePAC() {
	if atomic.CompareAndSwapInt32(&isPACOn, 1, 0) {
		log.Printf("Unsetting pangolin as system proxy")
		err := pac.Off()
		if err != nil {
			log.Printf("Unable to unset pangolin as system proxy: %s", err)
		}
		log.Printf("Unset pangolin as system proxy")
	}
}
