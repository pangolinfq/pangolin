package main

import (
	"crypto/rand"
	"crypto/tls"
	"flag"
	"github.com/pangolinfq/golibfq/mux"
	"github.com/pangolinfq/golibfq/obf"
	"github.com/pangolinfq/golibfq/sockstun"
	"github.com/pangolinfq/pangolin/utils"
	"github.com/yinghuocho/gosocks"
	"golang.org/x/net/websocket"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type websocketTunnelHandler struct {
	localSocksAddr string
	auth           sockstun.TunnelAuthenticator
	tlsConfig      *tls.Config
}

// websocket wraped with mux to tunnel SOCKS connections
func (h *websocketTunnelHandler) handler(websocketConn *websocket.Conn) {
	websocketConn.PayloadType = websocket.BinaryFrame

	var mask [obf.XorMaskLength]byte
	rand.Read(mask[:])
	obfedWs := obf.NewXorObfConn(websocketConn, mask)
	tlsConn := tls.Server(obfedWs, h.tlsConfig)

	muxServer := mux.NewServer(tlsConn)
	defer muxServer.Close()

	for {
		stream, err := muxServer.Accept()
		if err != nil {
			log.Printf("error accepting mux stream: %s", err)
			return
		}

		go func(tunnel net.Conn) {
			c, err := net.DialTimeout("tcp", h.localSocksAddr, time.Minute)
			if err != nil {
				log.Printf("error connecting SOCKS server: %s", err)
				stream.Close()
				return
			}
			socksConn := &gosocks.SocksConn{Conn: c.(*net.TCPConn), Timeout: 5 * time.Minute}
			if h.auth.ServerAuthenticate(tunnel, socksConn) != nil {
				stream.Close()
				socksConn.Close()
				return
			}
			sockstun.TunnelServer(tunnel, socksConn)
		}(stream)
	}
}

type serverOptions struct {
	logFilename    string
	pidFilename    string
	websocketAddr  string
	localSocksAddr string
	keyFile        string
	certFile       string
}

// read config file and overwrite config options in opts
func loadServerConfig(fileName string, opts *serverOptions) {
}

func main() {
	var opts serverOptions
	var configFile string

	flag.StringVar(&opts.websocketAddr, "websocket-addr", ":8000", "WebSocket server address")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:10800", "SOCKS server address")
	flag.StringVar(&opts.keyFile, "key-file", "./key.pem", "PEM eoncoded private key file")
	flag.StringVar(&opts.certFile, "cert-file", "./cert.pem", "PEM eoncoded certificate file")
	flag.StringVar(&configFile, "config", "", "config file")
	flag.StringVar(&opts.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&opts.pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()

	// read config
	if configFile != "" {
		loadServerConfig(configFile, &opts)
	}

	// load key pair
	cert, err := tls.LoadX509KeyPair(opts.certFile, opts.keyFile)
	if err != nil {
		log.Fatalf("FATAL: fail to load server cert: %s", err)
	}

	// initiate log file
	logFile := utils.RotateLog(opts.logFilename, nil)
	if opts.logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// a channel to receive quit signal from server daemons
	quit := make(chan bool)

	// start SOCKS server
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS address %s: %s", opts.localSocksAddr, err)
	}
	socksServer := gosocks.NewBasicServer(opts.localSocksAddr, 5*time.Minute)
	go func() {
		err := socksServer.Serve(socksListener)
		if err != nil {
			log.Printf("FATAL: error to serve SOCKS: %s", err)
		}
		close(quit)
	}()
	log.Printf("SOCKS server listens on %s", opts.localSocksAddr)

	// start WebSocket server
	websocketListener, err := net.Listen("tcp", opts.websocketAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on WebSocket address %s: %s", opts.websocketAddr, err)
	}

	go func() {
		h := &websocketTunnelHandler{
			localSocksAddr: opts.localSocksAddr,
			auth:           sockstun.NewTunnelAnonymousAuthenticator(),
			tlsConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		s := websocket.Server{
			Handler: websocket.Handler(h.handler),
		}
		err := http.Serve(websocketListener, s)
		if err != nil {
			log.Printf("FATAL: error to serve WebSocket: %s", err)
		}
		close(quit)
	}()
	log.Printf("WebSocket server listens on %s", opts.websocketAddr)

	// pidfile and clean up
	utils.SavePid(opts.pidFilename)
	defer socksListener.Close()
	defer websocketListener.Close()

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
