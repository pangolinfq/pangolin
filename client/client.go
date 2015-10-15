package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/pangolinfq/golibfq/mux"
	"github.com/pangolinfq/golibfq/obf"
	"github.com/pangolinfq/golibfq/sockstun"
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
	tlsConfig *tls.Config
	proxyIPs  []string
	proxyPort string
	ch        chan *tunnelRequest
	auth      sockstun.TunnelAuthenticator
}

// no explicit timeout, not clear whether this will hang forever
func (h *websocketTunnelHandler) dialMuxTunnel(addr string, result chan<- *mux.Client, quit <-chan bool) {
	var conn *mux.Client
	var mask [obf.XorMaskLength]byte
	var obfedWs net.Conn
	var tlsConn *tls.Conn

	wsUrl := url.URL{Scheme: "ws", Host: addr}
	ws, err := websocket.Dial(wsUrl.String(), "", wsUrl.String())
	if err != nil {
		log.Printf("error to connect WebSocket server %s: %s", addr, err)
		goto ret
	}
	log.Printf("WebSocket connected to %s", addr)
	ws.PayloadType = websocket.BinaryFrame

	rand.Read(mask[:])
	obfedWs = obf.NewXorObfConn(ws, mask)
	tlsConn = tls.Client(obfedWs, h.tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("error to accomplish TLS handshake with %s: %s", addr, err)
		tlsConn.Close()
		goto ret
	}
	log.Printf("TLS handshake accomplished with %s", addr)
	conn = mux.NewClient(tlsConn)

ret:
	select {
	case <-quit:
		if conn != nil {
			conn.Close()
		}
	case result <- conn:
	}
}

func (h *websocketTunnelHandler) muxClient() *mux.Client {
	ret := make(chan *mux.Client)
	quit := make(chan bool)

	for _, ip := range h.proxyIPs {
		addr := net.JoinHostPort(ip, h.proxyPort)
		go h.dialMuxTunnel(addr, ret, quit)
	}

	t := time.NewTimer(2 * time.Minute)
	failed := 0
	for {
		select {
		case conn := <-ret:
			if conn == nil {
				failed += 1
				if failed == len(h.proxyIPs) {
					log.Printf("all attemps to connect tunnel have failed")
				} else {
					continue
				}
			}
			close(quit)
			return conn

		case <-t.C:
			log.Printf("attempt to connect tunnel servers reached overall timeout")
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
	logFilename         string
	pidFilename         string
	remoteProxyNamePort string
	localSocksAddr      string
	resolvers           []string
	caCerts             string
}

// read config file and overwrite config options in opts
func loadClientConfig(fileName string, opts *clientOptions) {
}

// resolve namePort using mutiple resolvers, return addresses in the first response.
func resolveRemoteProxy(namePort string, resolvers []string, timeout time.Duration) []string {
	return []string{"127.0.0.1"}
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
	flag.StringVar(&opts.remoteProxyNamePort, "remote-proxy-addr", "127.0.0.1:8000", "WebSocket server address")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "SOCKS server address")
	flag.StringVar(&resolver, "dns-resolver", "8.8.8.8,8.8.4.4", "DNS resolvers")
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

	// resolve remote proxy address
	proxyName, proxyPort, err := net.SplitHostPort(opts.remoteProxyNamePort)
	if err != nil {
		log.Fatalf("FATAL: invalid proxy address: %s", opts.remoteProxyNamePort)
	}

	remoteProxyIPs := resolveRemoteProxy(proxyName, opts.resolvers, time.Minute)
	if remoteProxyIPs == nil {
		log.Fatalf("FATAL: fail to resolve %s using %s", opts.remoteProxyNamePort, opts.resolvers)
	}

	// a channel to receive quit signal from server daemons
	quit := make(chan bool)

	// start SOCKS server
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS address %s: %s", opts.localSocksAddr, err)
	}

	handler := &websocketTunnelHandler{
		tlsConfig: &tls.Config{
			ServerName: proxyName,
			RootCAs:    loadCaCerts(opts.caCerts),
		},
		proxyPort: proxyPort,
		proxyIPs:  remoteProxyIPs,
		ch:        make(chan *tunnelRequest),
		auth:      sockstun.NewTunnelAnonymousAuthenticator(),
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
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGHUP)

	running := true
	for running == true {
		select {
		case <-quit:
			log.Printf("FATAL: quit signal received")
			running = false
		case <-s:
			logFile = utils.RotateLog(opts.logFilename, logFile)
		}
	}
	log.Printf("done")
}
