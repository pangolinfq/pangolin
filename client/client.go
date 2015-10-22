package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/pangolinfq/golibfq/mux"
	"github.com/pangolinfq/golibfq/obf"
	"github.com/pangolinfq/golibfq/sockstun"
	r "github.com/pangolinfq/pangolin/rendezvous"
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
	"github.com/pangolinfq/pangolin/utils"
	"github.com/yinghuocho/gosocks"
	"golang.org/x/net/websocket"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type tunnelRequest struct {
	ret chan net.Conn
}

type websocketTunnelHandler struct {
	tlsConfig    *tls.Config
	rendezvousor r.Rendezvousor
	ch           chan *tunnelRequest
	auth         sockstun.TunnelAuthenticator

	proxyPeers []r.Peer
}

// no explicit timeout, not clear whether this will hang forever
func (h *websocketTunnelHandler) dialMuxTunnel(peer r.Peer, result chan<- *mux.Client, quit <-chan bool) {
	var ws *websocket.Conn
	var conf *websocket.Config
	var wsUrl url.URL

	ret := make(chan *mux.Client, 1)
	conn, err := peer.Connect(time.Minute)
	remoteAddr := conn.RemoteAddr().String()
	if err != nil {
		log.Printf("error to connect peer: %s", err)
		ret <- nil
		goto waiting
	}

	wsUrl = url.URL{Scheme: "ws", Host: remoteAddr}
	conf, _ = websocket.NewConfig(wsUrl.String(), wsUrl.String())
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
		ch <- mux.NewClient(tlsed)
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
				failed += 1
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
		} else {
			client = h.muxClient()
			if client == nil {
				return nil, nil
			}
			log.Printf("mux Client established.")
			continue
		}
	}
}

// with multiplexing
func (h *websocketTunnelHandler) run() {
	var client *mux.Client
	var stream *mux.Stream
	for {
		request := <-h.ch
		client, stream = h.muxStream(client)
		if stream == nil {
			close(request.ret)
		} else {
			request.ret <- stream
		}
	}
}

func (h *websocketTunnelHandler) ServeSocks(conn *gosocks.SocksConn) {
	r := &tunnelRequest{ret: make(chan net.Conn)}
	h.ch <- r
	tunnel, ok := <-r.ret
	if !ok {
		log.Printf("error to get a tunnel connection")
		gosocks.WriteSocksReply(conn, &gosocks.SocksReply{gosocks.SocksGeneralFailure, gosocks.SocksIPv4Host, "0.0.0.0", 0})
		conn.Close()
		return
	}
	close(r.ret)
	if h.auth.ClientAuthenticate(conn, tunnel) != nil {
		conn.Close()
		tunnel.Close()
		return
	}
	sockstun.TunnelClient(conn, tunnel)
}

type clientOptions struct {
	logFilename      string
	pidFilename      string
	remoteServerName string
	localSocksAddr   string
	resolvers        []string
	caCerts          string
	ecdnsPubKey      string
}

// read config file and overwrite config options in opts
func loadClientConfig(fileName string, opts *clientOptions) {
}

func loadCaCerts(path string) *x509.CertPool {
	certs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certs)
	return certPool
}

func main() {
	var opts clientOptions
	var resolver string
	var configFile string
	flag.StringVar(&opts.remoteServerName, "remote-server-name", "pangolinfq.org", "WebSocket server name")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "SOCKS server address")
	flag.StringVar(&resolver, "dns-resolver", "8.8.8.8:53,8.8.4.4:53", "DNS resolvers")
	flag.StringVar(&opts.ecdnsPubKey, "dns-pubkey-file", "./pub.pem", "PEM eoncoded ECDSA public key file")
	flag.StringVar(&opts.caCerts, "cacert", "", "trusted CA certificates")
	flag.StringVar(&configFile, "config", "", "config file")
	flag.StringVar(&opts.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&opts.pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()
	opts.resolvers = strings.Split(resolver, ",")

	// read config
	if configFile != "" {
		loadClientConfig(configFile, &opts)
	}

	// initiate log file
	logFile := utils.RotateLog(opts.logFilename, nil)
	if opts.logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// load public key for DNS verification
	ecdnsPubKey, err := ecdns.LoadPublicKey(opts.ecdnsPubKey)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA public key: %s", err)
	}

	dnsClient := &ecdns.Client{opts.resolvers, ecdnsPubKey}

	// a channel to receive quit signal from server daemons
	quit := make(chan bool)

	// start SOCKS server
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS address %s: %s", opts.localSocksAddr, err)
	}

	handler := &websocketTunnelHandler{
		tlsConfig: &tls.Config{
			ServerName: opts.remoteServerName,
			RootCAs:    loadCaCerts(opts.caCerts),
		},
		rendezvousor: dnsClient,
		ch:           make(chan *tunnelRequest),
		auth:         sockstun.NewTunnelAnonymousAuthenticator(),
	}
	go handler.run()
	socksServer := gosocks.NewServer(
		opts.localSocksAddr,
		5*time.Minute,
		handler,
		// let handler's authenticator to process SOCKS authentication
		nil,
	)
	go func() {
		err := socksServer.Serve(socksListener)
		if err != nil {
			log.Printf("FATAL: error to serve SOCKS: %s", err)
		}
		close(quit)
	}()
	log.Printf("SOCKS server listens on %s", opts.localSocksAddr)

	// pid file and clean up
	utils.SavePid(opts.pidFilename)
	defer socksListener.Close()

	// wait for control/quit signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		select {
		case <-quit:
			log.Printf("quit signal received")
			break loop
		case s := <-c:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				break loop
			case syscall.SIGHUP:
				logFile = utils.RotateLog(opts.logFilename, logFile)
			}
		}
	}
	log.Printf("done")
}
