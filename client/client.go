package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/elazarl/goproxy"
	"github.com/pangolinfq/golibfq/http2socks"
	"github.com/pangolinfq/golibfq/sockstun"
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
	"github.com/pangolinfq/pangolin/utils"
	"github.com/yinghuocho/gosocks"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type clientOptions struct {
	logFilename         string
	pidFilename         string
	tunnelingDomainFile string
	tunnelServerName    string
	localSocksAddr      string
	localHttpAddr       string
	tunnelClientAddr    string
	resolvers           []string
	caCerts             string
	ecdnsPubKey         string
}

// read config file and overwrite config options in opts
func loadClientConfig(filename string, opts *clientOptions) {
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

func loadTunnelingDomains(filename string) map[string]bool {
	ret := make(map[string]bool)
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("fail to load tunneling domains from %s: %s", filename, err)
		return ret
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ret[strings.Trim(scanner.Text(), " \r\n ")] = true
	}
	return ret
}

func main() {
	var opts clientOptions
	var resolver string
	var configFile string
	flag.StringVar(&opts.tunnelServerName, "tunnel-server-name", "rendezvous.pangolinfq.org", "tunnel server name")
	flag.StringVar(&opts.tunnelClientAddr, "tunnel-client-addr", "127.0.0.1:10888", "tunnel client(SOCKS) address")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "SOCKS proxy address")
	flag.StringVar(&opts.localHttpAddr, "local-http-addr", "127.0.0.1:8088", "HTTP proxy address")
	flag.StringVar(&resolver, "dns-resolver", "8.8.8.8:53,8.8.4.4:53", "DNS resolvers")
	flag.StringVar(&opts.ecdnsPubKey, "dns-pubkey-file", "./pub.pem", "PEM eoncoded ECDSA public key file")
	flag.StringVar(&opts.tunnelingDomainFile, "tunneling-domain-file", "./domain.txt", "domains through tunnel")
	flag.StringVar(&opts.caCerts, "cacert", "./cacert.pem", "trusted CA certificates")
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

	// a channel to receive quit signal from proxy daemons
	quit := make(chan bool)

	// start tunnel client
	tunnelListener, err := net.Listen("tcp", opts.tunnelClientAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on tunnel client (SOCKS) address %s: %s", opts.localSocksAddr, err)
	}
	tunnelHandler := &websocketTunnelHandler{
		tlsConfig: &tls.Config{
			ServerName: opts.tunnelServerName,
			RootCAs:    loadCaCerts(opts.caCerts),
		},
		rendezvousor: dnsClient,
		ch:           make(chan *tunnelRequest),
		auth:         sockstun.NewTunnelAnonymousAuthenticator(),
	}
	go tunnelHandler.run()
	tunnelClient := gosocks.NewServer(
		opts.localSocksAddr,
		5*time.Minute,
		tunnelHandler,
		// let handler's authenticator to process SOCKS authentication
		nil,
	)
	go func() {
		err := tunnelClient.Serve(tunnelListener)
		if err != nil {
			log.Printf("FATAL: error to start tunnel client (SOCKS): %s", err)
		}
		close(quit)
	}()
	log.Printf("tunnel client (SOCKS) listens on %s", opts.tunnelClientAddr)

	// start SOCKS proxy
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS proxy address %s: %s", opts.localSocksAddr, err)
	}
	socksHandler := &forwardingHandler{
		basic:            &gosocks.BasicSocksHandler{},
		tunnelAddr:       opts.tunnelClientAddr,
		tunnelingDomains: loadTunnelingDomains(opts.tunnelingDomainFile),
	}
	socksProxy := gosocks.NewServer(
		opts.localSocksAddr,
		5*time.Minute,
		socksHandler,
		&gosocks.AnonymousServerAuthenticator{},
	)
	go func() {
		err := socksProxy.Serve(socksListener)
		if err != nil {
			log.Printf("FATAL: error to start SOCKS proxy: %s", err)
		}
		close(quit)
	}()
	log.Printf("SOCKS proxy listens on %s", opts.localSocksAddr)

	// start HTTP proxy
	httpListener, err := net.Listen("tcp", opts.localHttpAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on HTTP/S proxy address %s: %s", opts.localHttpAddr, err)
	}

	socksDialer := &gosocks.SocksDialer{
		Timeout: 5 * time.Minute,
		Auth:    &gosocks.AnonymousClientAuthenticator{},
	}
	socksConverter := goproxyHttp2SocksConverter{
		converter: http2socks.Http2SocksConverter{
			SocksDialer: socksDialer,
			SocksAddr:   opts.localSocksAddr,
		},
	}
	httpProxy := goproxy.NewProxyHttpServer()
	httpProxy.OnRequest().DoFunc(socksConverter.goproxyHttp2Socks)
	httpProxy.OnRequest().HandleConnectFunc(socksConverter.goproxyHttps2Socks)
	go http.Serve(httpListener, httpProxy)
	log.Printf("HTTP/S proxy listens on %s", opts.localHttpAddr)

	// pid file and clean up
	utils.SavePid(opts.pidFilename)
	defer tunnelListener.Close()
	defer httpListener.Close()

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
