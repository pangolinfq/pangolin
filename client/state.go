package main

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"log"
)

type pangolinState struct {
	trackingID string
	httpClient *http.Client
	ch         chan string
}

func newState(trackingID string, proxyURL *url.URL) *pangolinState {
	return &pangolinState{
		trackingID: trackingID,
		httpClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: time.Minute,
		},
		ch: make(chan string, 10),
	}
}

func (s *pangolinState) reportEvent(category, action string) {
	log.Printf("report google analytics event: [%s %s]", category, action)
	resp, err := s.httpClient.PostForm("https://www.google-analytics.com/collect", url.Values{
		"v":   {"1"},
		"tid": {s.trackingID},
		"cid": {"35009a79-1a05-49d7-b876-2b884d0f825b"},
		"an":  {"Pangolin"},
		"av":  {PANGOLIN_VERSION},
		"t":   {"event"},
		"ec":  {category},
		"ea":  {action},
		"el":  {strings.Join([]string{runtime.GOOS, runtime.GOARCH}, "_")},
	})
	if err != nil {
		log.Printf("error to report google analytics event: %s", err)
	} else {
		resp.Body.Close()
	}
}

func (s *pangolinState) event(category string, action string) {
	s.ch <- strings.Join([]string{"event", category, action}, "|")
}

func (s *pangolinState) run() {
	for {
		cmd := <-s.ch
		switch {
		case strings.HasPrefix(cmd, "event"):
			args := strings.Split(cmd, "|")
			s.reportEvent(args[1], args[2])
		}
	}
}
