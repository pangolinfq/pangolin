package ui

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

var (
	uiHandler *http.ServeMux
	uiServer  *http.Server
	uiURL     string
)

func index(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello"))
}

func StartUI(l net.Listener) {
	uiURL = fmt.Sprintf("http://%s", l.Addr().String())
	uiHandler = http.NewServeMux()
	uiHandler.Handle("/", http.HandlerFunc(index))
	uiServer = &http.Server{
		Handler: uiHandler,
	}
	go func() {
		err := uiServer.Serve(l)
		if err != nil {
			log.Fatalf("FATAL: UI stopped")
		}
	}()
}

func Handle(path string, handler http.Handler) string {
	uiHandler.Handle(path, handler)
	return uiURL + path
}
