package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/getlantern/i18n"
	"github.com/getlantern/systray"
	"github.com/pangolinfq/golibfq/chain"
	"github.com/pangolinfq/golibfq/sockstun"
	"github.com/pangolinfq/pangolin/client/autopac"
	"github.com/pangolinfq/pangolin/client/ui"
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
	"github.com/pangolinfq/pangolin/utils"
	"github.com/yinghuocho/gosocks"
)

type clientOptions struct {
	logFilename         string
	pidFilename         string
	tunnelingDomainFile string
	tunnelingAll        bool
	tunnelServerName    string
	localSocksAddr      string
	localHTTPAddr       string
	resolvers           []string
	caCerts             string
	ecdnsPubKey         string
}

var (
	opts        clientOptions
	exitCh      = make(chan error, 1)
	chExitFuncs = make(chan func(), 10)
)

// read config file and overwrite config options in opts
func loadClientConfig(filename string) {
}

func loadCaCerts(path string) *x509.CertPool {
	var certs []byte
	var err error
	if path != "" {
		certs, err = ioutil.ReadFile(path)
	} else {
		certs, err = Asset("resources/keys/cacert.pem")
	}
	if err != nil {
		return nil
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certs)
	return certPool
}

func loadDNSKey(path string) (*ecdsa.PublicKey, error) {
	if path != "" {
		return ecdns.LoadPublicKeyFile(opts.ecdnsPubKey)
	}

	data, err := Asset("resources/keys/dnspub.pem")
	if err != nil {
		return nil, err
	}
	return ecdns.LoadPublicKeyBytes(data)
}

func loadTunnelingDomains(path string) map[string]bool {
	ret := make(map[string]bool)
	var scanner *bufio.Scanner

	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			log.Printf("fail to load tunneling domains from %s: %s", path, err)
			return nil
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		data, err := Asset("resources/domains.txt")
		if err != nil {
			log.Printf("fail to load embedded domains: %s", err)
			return nil
		}
		scanner = bufio.NewScanner(bytes.NewBuffer(data))
	}

	for scanner.Scan() {
		s := strings.Trim(scanner.Text(), " \r\n ")
		if !strings.HasPrefix(s, "#") {
			ret[s] = true
		}
	}
	return ret
}

func parseFlags(configFile *string) {
	var resolvers string
	flag.StringVar(&opts.tunnelServerName, "tunnel-server-name", "rendezvous.pangolinfq.org", "tunnel server name")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:3080", "SOCKS proxy address")
	flag.StringVar(&opts.localHTTPAddr, "local-http-addr", "127.0.0.1:8088", "HTTP proxy address")
	flag.StringVar(&resolvers, "dns-resolver", "8.8.8.8:53,8.8.4.4:53,209.244.0.3:53,209.244.0.4:53,64.6.64.6:53,64.6.65.6:53,208.67.222.222:53,208.67.220.220:53,77.88.8.8:53,77.88.8.1:53", "DNS resolvers")
	flag.StringVar(&opts.ecdnsPubKey, "dns-pubkey-file", "", "PEM eoncoded ECDSA public key file, use embedded public key if not specified")
	flag.StringVar(&opts.tunnelingDomainFile, "tunneling-domain-file", "", "domains through tunnel, use embedded domain list if not specified")
	flag.BoolVar(&opts.tunnelingAll, "tunneling-all", false, "whether tunneling all traffic")
	flag.StringVar(&opts.caCerts, "cacert", "", "trusted CA certificates, use embedded certs if not specified")
	flag.StringVar(configFile, "config", "", "config file")
	flag.StringVar(&opts.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&opts.pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()
	opts.resolvers = strings.Split(resolvers, ",")
}

// addExitFunc adds a function to be called before the application exits.
func addExitFunc(exitFunc func()) {
	chExitFuncs <- exitFunc
}

// exit tells the application to exit, optionally supplying an error that caused
// the exit.
func exit(err error) {
	defer func() { exitCh <- err }()
	for {
		select {
		case f := <-chExitFuncs:
			log.Printf("Calling exit func")
			f()
		default:
			log.Printf("No exit func remaining, exit now")
			return
		}
	}
}

// Handle system signals for clean exit
func handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-c
		log.Printf("Got signal \"%s\", exiting...", s)
		exit(nil)
	}()
}

func waitForExit() error {
	return <-exitCh
}

func configureSystray() {
	icon, err := Asset("resources/icons/24.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for system tray: %s", err)
	}
	systray.SetIcon(icon)
	systray.SetTooltip("Pangolin")
	quit := systray.AddMenuItem(i18n.T("TRAY_QUIT"), i18n.T("QUIT"))

	go func() {
		for {
			select {
			//case <-show.ClickedCh:
			//	ui.Show()
			case <-quit.ClickedCh:
				exit(nil)
				return
			}
		}
	}()
}

func configureI18n() {
	i18n.SetMessagesFunc(func(filename string) ([]byte, error) {
		return Asset(fmt.Sprintf("resources/locale/%s", filename))
	})
	if err := i18n.UseOSLocale(); err != nil {
		log.Printf("i18n.UseOSLocale: %q", err)
	}
}

func _main() {
	var configFile string

	// parse flags
	parseFlags(&configFile)

	// read config
	if configFile != "" {
		loadClientConfig(configFile)
	}

	// initiate log file
	logFile := utils.RotateLog(opts.logFilename, nil)
	if opts.logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// load public key for DNS verification
	ecdnsPubKey, err := loadDNSKey(opts.ecdnsPubKey)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA public key: %s", err)
	}
	dnsClient := &ecdns.Client{Resolvers: opts.resolvers, PubKey: ecdnsPubKey}

	// start tunnel client
	tunnelListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log.Fatalf("FATAL: fail to listen on tunnel client (SOCKS): %s", err)
	}
	tunnelClientAddr := tunnelListener.Addr().String()
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
		exit(err)
	}()
	log.Printf("tunnel client (SOCKS) listens on %s", tunnelClientAddr)

	// start SOCKS proxy
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS proxy address %s: %s", opts.localSocksAddr, err)
	}
	domains := loadTunnelingDomains(opts.tunnelingDomainFile)
	socksHandler := &forwardingHandler{
		basic:      &gosocks.BasicSocksHandler{},
		tunnelAddr: tunnelClientAddr,
	}

	if opts.tunnelingAll || domains == nil || len(domains) == 0 {
		log.Printf("Pangolin will tunnel all traffic")
		socksHandler.tunnelingAll = true
	} else {
		socksHandler.tunnelingAll = false
		socksHandler.tunnelingDomains = domains
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
		exit(err)
	}()
	log.Printf("SOCKS proxy listens on %s", opts.localSocksAddr)

	// start HTTP proxy
	httpListener, err := net.Listen("tcp", opts.localHTTPAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on HTTP/S proxy address %s: %s", opts.localHTTPAddr, err)
	}

	socksDialer := &gosocks.SocksDialer{
		Timeout: 5 * time.Minute,
		Auth:    &gosocks.AnonymousClientAuthenticator{},
	}
	http2Socks := chain.GoproxySocksChain{
		Chain: chain.HTTPSocksChain{
			SocksDialer: socksDialer,
			SocksAddr:   opts.localSocksAddr,
		},
	}
	httpProxy := goproxy.NewProxyHttpServer()
	httpProxy.OnRequest().DoFunc(http2Socks.HTTP)
	httpProxy.OnRequest().HandleConnectFunc(http2Socks.HTTPS)
	go http.Serve(httpListener, httpProxy)
	log.Printf("HTTP/S proxy listens on %s", opts.localHTTPAddr)

	// i18n
	configureI18n()

	// start web based UI
	uiListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log.Fatalf("FATAL: fail to listen on UI (HTTP) address: %s", err)
	}
	ui.StartUI(uiListener)

	// pid file
	utils.SavePid(opts.pidFilename)

	// clean exit with signals
	go handleSignals()

	// set PAC
	icon, err := Asset("resources/icons/32.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for PAC: %s", err)
	}
	err = autopac.PromptPrivilegeEscalation(icon)
	if err != nil {
		log.Fatalf("Unable to escalate priviledge for setting PAC: %s", err)
	}
	autopac.EnablePAC(httpListener.Addr().String())
	addExitFunc(autopac.DisablePAC)

	// systray
	addExitFunc(systray.Quit)
	configureSystray()

	waitForExit()
	os.Exit(0)
}

func main() {
	systray.Run(_main)
}
