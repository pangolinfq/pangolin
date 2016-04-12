package main

import (
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

type pangolinState struct {
	trackingID string
	clientID   string
	httpClient *http.Client
	ch         chan string
}

func newState(clientID string, trackingID string, proxyURL *url.URL) *pangolinState {
	return &pangolinState{
		trackingID: trackingID,
		clientID:   clientID,
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
		"cid": {s.clientID},
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
