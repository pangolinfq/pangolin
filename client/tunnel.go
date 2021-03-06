package main

import (
	"crypto/rand"
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/yinghuocho/golibfq/mux"
	"github.com/yinghuocho/golibfq/obf"
	"github.com/yinghuocho/golibfq/sockstun"
	"github.com/yinghuocho/gosocks"
	"golang.org/x/net/websocket"
	
	r "github.com/pangolinfq/pangolin/rendezvous"
)

type tunnelRequest struct {
	ret chan net.Conn
}

type websocketTunnelHandler struct {
	tlsConfig    *tls.Config
	rendezvousor r.Rendezvousor
	ch           chan *tunnelRequest
	quit         chan bool
	auth         sockstun.TunnelAuthenticator

	proxyPeers []r.Peer
}

func (h *websocketTunnelHandler) dialMuxTunnel(peer r.Peer, result chan<- *mux.Client, quit <-chan bool) {
	var ws *websocket.Conn
	var remoteAddr string
	var conf *websocket.Config
	var wsURL url.URL

	ret := make(chan *mux.Client, 1)
	conn, err := peer.Connect(time.Minute)
	if err != nil {
		log.Printf("error to connect peer: %s", err)
		ret <- nil
		goto waiting
	}
	remoteAddr = conn.RemoteAddr().String()
	wsURL = url.URL{Scheme: "ws", Host: remoteAddr}
	conf, _ = websocket.NewConfig(wsURL.String(), wsURL.String())
	ws, err = websocket.NewClient(conf, conn)
	if err != nil {
		log.Printf("error to connect WebSocket server: %s", err)
		ret <- nil
		goto waiting
	}

	log.Printf("WebSocket connected to %s", conn.RemoteAddr().String())
	go func(c *websocket.Conn, a string, ch chan<- *mux.Client) {
		var mask [obf.XorMaskLength]byte
		c.PayloadType = websocket.BinaryFrame
		rand.Read(mask[:])
		obfed := obf.NewXorObfConn(c, mask)
		tlsed := tls.Client(obfed, h.tlsConfig)
		err := tlsed.Handshake()
		if err != nil {
			log.Printf("error to accomplish TLS handshake %s: %s", a, err)
			tlsed.Close()
			ch <- nil
		}
		log.Printf("TLS handshake accomplished with %s", a)
		cient := mux.NewClient(tlsed)
		cient.SetIdleTime(5 * time.Minute)
		ch <- cient
	}(ws, remoteAddr, ret)

waiting:
	select {
	case <-quit:
		if ws != nil {
			ws.Close()
		}
	case conn := <-ret:
		select {
		case <-quit:
			if ws != nil {
				ws.Close()
			}
		case result <- conn:
		}
	}
}

func (h *websocketTunnelHandler) muxClient() *mux.Client {
	if h.proxyPeers == nil {
		h.proxyPeers = h.rendezvousor.Query(h.tlsConfig.ServerName, time.Minute)
		if h.proxyPeers == nil {
			log.Printf("fail to get valid peers by querying %s", h.tlsConfig.ServerName)
			return nil
		}
	}

	ret := make(chan *mux.Client)
	quit := make(chan bool)
	for _, peer := range h.proxyPeers {
		go h.dialMuxTunnel(peer, ret, quit)
	}

	t := time.NewTimer(2 * time.Minute)
	failed := 0
	for {
		select {
		case conn := <-ret:
			if conn == nil {
				failed++
				if failed == len(h.proxyPeers) {
					log.Printf("all attemps to connect tunnel have failed")
					h.proxyPeers = nil
				} else {
					continue
				}
			}
			close(quit)
			return conn

		case <-t.C:
			log.Printf("attempt to connect tunnel servers reached overall timeout")
			h.proxyPeers = nil
			close(quit)
			return nil
		}
	}
}

func (h *websocketTunnelHandler) muxStream(client *mux.Client) (*mux.Client, *mux.Stream) {
	var err error
	var stream *mux.Stream

	for {
		if client != nil {
			stream, err = client.OpenStream()
			if err != nil {
				client.Close()
				client = nil
				log.Printf("mux Client aborted.")
				continue
			}
			return client, stream
		}
		client = h.muxClient()
		if client == nil {
			return nil, nil
		}
		log.Printf("mux Client established.")
	}
}

func (h *websocketTunnelHandler) run() {
	var client *mux.Client
	var stream *mux.Stream
	for {
		select {
		case request := <-h.ch:
			client, stream = h.muxStream(client)
			if stream == nil {
				close(request.ret)
			} else {
				request.ret <- stream
			}
		case <-h.quit:
			break
		}
	}
}

func (h *websocketTunnelHandler) ServeSocks(conn *gosocks.SocksConn) {
	r := &tunnelRequest{ret: make(chan net.Conn)}
	h.ch <- r
	tunnel, ok := <-r.ret
	if !ok {
		log.Printf("error to get a tunnel connection")
		conn.Close()
		return
	}
	if h.auth.ClientAuthenticate(conn, tunnel) != nil {
		conn.Close()
		tunnel.Close()
		return
	}
	sockstun.TunnelClient(conn, tunnel)
}

func (h *websocketTunnelHandler) Quit() {
	close(h.quit)
}
