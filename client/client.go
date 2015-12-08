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
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/getlantern/i18n"
	"github.com/getlantern/systray"
	"github.com/pangolinfq/golibfq/chain"
	"github.com/pangolinfq/golibfq/sockstun"
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
	"github.com/pangolinfq/pangolin/utils"
	"github.com/pangolinfq/tarfs"
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
	localUIAddr         string
	resolvers           []string
	caCerts             string
	ecdnsPubKey         string
	landingPage         string
}

type pangolinClient struct {
	fs      *tarfs.FileSystem
	options clientOptions
	appData *utils.AppData

	dnsClient      *ecdns.Client
	tunnelListener net.Listener
	tunnelProxy    *gosocks.Server
	socksHandler   *forwardingHandler
	socksListener  net.Listener
	socksProxy     *gosocks.Server
	httpListener   net.Listener
	httpProxy      *goproxy.ProxyHttpServer
	ui             *pangolinUI

	exitCh      chan error
	chExitFuncs chan func()
}

func (c *pangolinClient) version() string {
	return fmt.Sprintf("Pangolin-%s 0.0.1dev", runtime.GOOS)
}

func (c *pangolinClient) loadCaCerts(path string) *x509.CertPool {
	var certs []byte
	var err error
	if path != "" {
		certs, err = ioutil.ReadFile(path)
	} else {
		certs, err = c.fs.Get("keys/cacert.pem")
	}
	if err != nil {
		return nil
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certs)
	return certPool
}

func (c *pangolinClient) loadDNSKey(path string) (*ecdsa.PublicKey, error) {
	if path != "" {
		return ecdns.LoadPublicKeyFile(path)
	}

	data, err := c.fs.Get("keys/dnspub.pem")
	if err != nil {
		return nil, err
	}
	return ecdns.LoadPublicKeyBytes(data)
}

func (c *pangolinClient) loadTunnelingDomains(path string) map[string]bool {
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
		data, err := c.fs.Get("domains.txt")
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

func (c *pangolinClient) configureI18n() {
	i18n.SetMessagesFunc(func(filename string) ([]byte, error) {
		return c.fs.Get(fmt.Sprintf("locale/%s", filename))
	})
	if err := i18n.UseOSLocale(); err != nil {
		log.Printf("i18n.UseOSLocale: %q", err)
	}
}

// addExitFunc adds a function to be called before the application exits.
func (c *pangolinClient) addExitFunc(exitFunc func()) {
	c.chExitFuncs <- exitFunc
}

// exit tells the application to exit, optionally supplying an error that caused
// the exit.
func (c *pangolinClient) exit(err error) {
	defer func() { c.exitCh <- err }()
	for {
		select {
		case f := <-c.chExitFuncs:
			log.Printf("Calling exit func")
			f()
		default:
			log.Printf("No exit func remaining, exit now")
			return
		}
	}
}

func (c *pangolinClient) getLocalSocksAddr() string {
	if c.appData != nil {
		addr, ok := c.appData.Get("localSocksAddr")
		if ok {
			return addr
		}
	}

	return c.options.localSocksAddr
}

func (c *pangolinClient) getLocalHTTPAddr() string {
	if c.appData != nil {
		addr, ok := c.appData.Get("localHTTPAddr")
		if ok {
			return addr
		}
	}

	return c.options.localHTTPAddr
}

func (c *pangolinClient) isTunnelingAll(domains map[string]bool) bool {
	if c.options.tunnelingAll {
		return true
	}
	if domains == nil || len(domains) == 0 {
		return true
	}
	if c.appData != nil {
		v, ok := c.appData.Get("tunnelingAll")
		if ok && v == "1" {
			return true
		}
	}
	return false
}

func (c *pangolinClient) openSettingsPage() bool {
	if c.appData != nil {
		v, ok := c.appData.Get("openSettingsPage")
		if ok && v == "0" {
			return false
		}
	}
	return true
}

func (c *pangolinClient) openLandingPage() bool {
	if c.appData != nil {
		v, ok := c.appData.Get("openLandingPage")
		if ok && v == "0" {
			return false
		}
	}
	return true
}

// Handle system signals for clean exit
func (c *pangolinClient) handleSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-ch
		log.Printf("Got signal \"%s\", exiting...", s)
		c.exit(nil)
	}()
}

func (c *pangolinClient) waitForExit() error {
	return <-c.exitCh
}

func (c *pangolinClient) configureSystray() {
	icon, err := c.fs.Get("icons/24.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for system tray: %s", err)
	}
	systray.SetIcon(icon)
	systray.SetTooltip("Pangolin")
	settings := systray.AddMenuItem(i18n.T("TRAY_SETTINGS"), "")
	quit := systray.AddMenuItem(i18n.T("TRAY_QUIT"), "")
	go func() {
		for {
			select {
			case <-settings.ClickedCh:
				c.ui.show()
			case <-quit.ClickedCh:
				c.exit(nil)
				return
			}
		}
	}()
}

func (c *pangolinClient) parseFlags() {
	var resolvers string
	flag.StringVar(&c.options.tunnelServerName, "tunnel-server-name", "rendezvous.pangolinfq.org", "tunnel server name")
	flag.StringVar(&c.options.localSocksAddr, "local-socks-addr", "127.0.0.1:23080", "SOCKS proxy address")
	flag.StringVar(&c.options.localHTTPAddr, "local-http-addr", "127.0.0.1:28088", "HTTP proxy address")
	flag.StringVar(&c.options.localUIAddr, "local-ui-addr", "127.0.0.1:28089", "Web UI address, use random local address when specified address is not available")
	flag.StringVar(&resolvers, "dns-resolver", "8.8.8.8:53,8.8.4.4:53,209.244.0.3:53,209.244.0.4:53,64.6.64.6:53,64.6.65.6:53,208.67.222.222:53,208.67.220.220:53,77.88.8.8:53,77.88.8.1:53", "DNS resolvers")
	flag.StringVar(&c.options.ecdnsPubKey, "dns-pubkey-file", "", "PEM eoncoded ECDSA public key file, use embedded public key if not specified")
	flag.StringVar(&c.options.tunnelingDomainFile, "tunneling-domain-file", "", "domains through tunnel, use embedded domain list if not specified")
	flag.BoolVar(&c.options.tunnelingAll, "tunneling-all", false, "whether tunneling all traffic")
	flag.StringVar(&c.options.caCerts, "cacert", "", "trusted CA certificates, use embedded certs if not specified")
	flag.StringVar(&c.options.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&c.options.pidFilename, "pidfile", "", "file to save process id")
	flag.StringVar(&c.options.landingPage, "landing-page", "https://www.google.com/", "landing page")
	flag.Parse()
	c.options.resolvers = strings.Split(resolvers, ",")
}

func (c *pangolinClient) _main() {
	// parse flags
	c.parseFlags()
	var err error
	c.fs, err = tarfs.New(Resources, "")
	if err != nil {
		log.Fatalf("FATAL: fail to load embedded resources: %s", err)
	}

	c.appData, err = utils.OpenAppData("pangolin")
	if err != nil {
		log.Printf("WARNING: unable to load/store customized settings: %s", err)
	}

	// initiate log file
	logFile := utils.RotateLog(c.options.logFilename, nil)
	if c.options.logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// load public key for DNS verification
	ecdnsPubKey, err := c.loadDNSKey(c.options.ecdnsPubKey)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA public key: %s", err)
	}
	c.dnsClient = &ecdns.Client{Resolvers: c.options.resolvers, PubKey: ecdnsPubKey}

	// start tunnel client
	c.tunnelListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log.Fatalf("FATAL: fail to listen on tunnel client (SOCKS): %s", err)
	}
	tunnelProxyAddr := c.tunnelListener.Addr().String()
	tunnelHandler := &websocketTunnelHandler{
		tlsConfig: &tls.Config{
			ServerName: c.options.tunnelServerName,
			RootCAs:    c.loadCaCerts(c.options.caCerts),
		},
		rendezvousor: c.dnsClient,
		ch:           make(chan *tunnelRequest),
		auth:         sockstun.NewTunnelAnonymousAuthenticator(),
	}
	go tunnelHandler.run()
	c.tunnelProxy = gosocks.NewServer(
		c.options.localSocksAddr,
		5*time.Minute,
		tunnelHandler,
		// let handler's authenticator to process SOCKS authentication
		nil,
	)
	go func() {
		err := c.tunnelProxy.Serve(c.tunnelListener)
		if err != nil {
			log.Printf("FATAL: error to serve tunnel client (SOCKS): %s", err)
		}
		c.exit(err)
	}()
	log.Printf("tunnel proxy (SOCKS) listens on %s", tunnelProxyAddr)

	// start SOCKS proxy
	localSocksAddr := c.getLocalSocksAddr()
	c.socksListener, err = net.Listen("tcp", localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS proxy address %s: %s", localSocksAddr, err)
	}
	domains := c.loadTunnelingDomains(c.options.tunnelingDomainFile)
	c.socksHandler = &forwardingHandler{
		basic:      &gosocks.BasicSocksHandler{},
		tunnelAddr: tunnelProxyAddr,
	}
	c.socksHandler.tunnelingDomains = domains
	c.socksHandler.tunnelingAll = c.isTunnelingAll(domains)
	c.socksProxy = gosocks.NewServer(
		localSocksAddr,
		5*time.Minute,
		c.socksHandler,
		&gosocks.AnonymousServerAuthenticator{},
	)
	go func() {
		err := c.socksProxy.Serve(c.socksListener)
		if err != nil {
			log.Printf("FATAL: error to serve SOCKS proxy: %s", err)
		}
		c.exit(err)
	}()
	log.Printf("SOCKS proxy listens on %s", localSocksAddr)

	// start HTTP proxy
	localHTTPAddr := c.getLocalHTTPAddr()
	c.httpListener, err = net.Listen("tcp", localHTTPAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on HTTP/S proxy address %s: %s", localHTTPAddr, err)
	}
	socksDialer := &gosocks.SocksDialer{
		Timeout: 5 * time.Minute,
		Auth:    &gosocks.AnonymousClientAuthenticator{},
	}
	http2Socks := chain.GoproxySocksChain{
		Chain: chain.HTTPSocksChain{
			SocksDialer: socksDialer,
			SocksAddr:   localSocksAddr,
		},
	}
	c.httpProxy = goproxy.NewProxyHttpServer()
	c.httpProxy.OnRequest().DoFunc(http2Socks.HTTP)
	c.httpProxy.OnRequest().HandleConnectFunc(http2Socks.HTTPS)
	go func() {
		err := http.Serve(c.httpListener, c.httpProxy)
		if err != nil {
			log.Printf("FATAL: error to serve HTTP/S proxy: %s", err)
		}
		c.exit(err)
	}()
	log.Printf("HTTP/S proxy listens on %s", localHTTPAddr)

	// i18n
	c.configureI18n()

	// start web based UI
	uiListener, err := net.Listen("tcp", c.options.localUIAddr)
	if err != nil {
		uiListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		log.Printf("fail to listen on specified UI (HTTP) address: %s", err)
		log.Printf("try to use random local address")
		if err != nil {
			log.Fatalf("FATAL: fail to listen on UI (HTTP) address: %s", err)
		}
	}
	c.ui = startUI(c, uiListener)

	// set PAC
	icon, err := c.fs.Get("icons/24.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for PAC: %s", err)
	}
	err = promptPrivilegeEscalation(icon)
	if err != nil {
		log.Fatalf("Unable to escalate priviledge for setting PAC: %s", err)
	}
	pacURL := c.ui.handle(pacPath(), pacHandler(c.httpListener.Addr().String()))
	enablePAC(pacURL)
	c.addExitFunc(disablePAC)

	// open starting pages
	if c.openSettingsPage() {
		c.ui.show()
	}
	if c.openLandingPage() {
		c.ui.open(c.options.landingPage)
	}

	// pid file
	utils.SavePid(c.options.pidFilename)

	// clean exit with signals
	go c.handleSignals()

	// systray
	c.addExitFunc(systray.Quit)
	c.configureSystray()

	c.waitForExit()
	os.Exit(0)
}

func (c *pangolinClient) tunnelingAllOn() {
	c.socksHandler = &forwardingHandler{
		basic:      &gosocks.BasicSocksHandler{},
		tunnelAddr: c.tunnelListener.Addr().String(),
	}
	c.socksHandler.tunnelingAll = true
	c.socksProxy.ChangeHandler(c.socksHandler)
	if c.appData != nil {
		c.appData.Put("tunnelingAll", "1")
	}
}

func (c *pangolinClient) tunnelingAllOff() {
	if c.appData != nil {
		c.appData.Put("tunnelingAll", "0")
	}

	domains := c.loadTunnelingDomains(c.options.tunnelingDomainFile)
	c.socksHandler = &forwardingHandler{
		basic:      &gosocks.BasicSocksHandler{},
		tunnelAddr: c.tunnelListener.Addr().String(),
	}
	c.socksHandler.tunnelingDomains = domains
	c.socksHandler.tunnelingAll = false
	c.socksProxy.ChangeHandler(c.socksHandler)
}

func (c *pangolinClient) openSettingsPageOn() {
	if c.appData != nil {
		c.appData.Put("openSettingsPage", "1")
	}
}

func (c *pangolinClient) openSettingsPageOff() {
	if c.appData != nil {
		c.appData.Put("openSettingsPage", "0")
	}
}

func (c *pangolinClient) openLandingPageOn() {
	if c.appData != nil {
		c.appData.Put("openLandingPage", "1")
	}
}

func (c *pangolinClient) openLandingPageOff() {
	if c.appData != nil {
		c.appData.Put("openLandingPage", "0")
	}
}

func main() {
	client := &pangolinClient{
		exitCh:      make(chan error, 1),
		chExitFuncs: make(chan func(), 10),
	}
	systray.Run(client._main)
}
