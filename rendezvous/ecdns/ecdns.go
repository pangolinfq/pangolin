package ecdns

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/miekg/dns"
	r "github.com/pangolinfq/pangolin/rendezvous"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Client implements Rendezvousor interface
type Client struct {
	Resolvers []string
	PubKey    *ecdsa.PublicKey
}

func LoadPublicKey(filename string) (*ecdsa.PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("couldn't decode PEM file")
	}

	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubkey.(*ecdsa.PublicKey), nil
}

func LoadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("couldn't decode PEM file")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func decodeInt(s string) *big.Int {
	v, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	i := big.NewInt(0).SetBytes(v)
	return i
}

func parseAndVerify(data []byte, pubKey *ecdsa.PublicKey) ([]r.Peer, error) {
	in := new(dns.Msg)
	err := in.Unpack(data)
	if err != nil {
		return nil, err
	}

	if len(in.Answer) <= 0 || in.Answer[0].Header().Rrtype != dns.TypeTXT {
		return nil, errors.New("invalid DNS response")
	}

	encodedVal := in.Answer[0].(*dns.TXT).Txt[0]
	encodedSigR := in.Answer[0].(*dns.TXT).Txt[1]
	encodedSigS := in.Answer[0].(*dns.TXT).Txt[2]

	if err != nil {
		return nil, errors.New("invalid TXT value")
	}

	sigR := decodeInt(encodedSigR)
	sigS := decodeInt(encodedSigS)
	if sigR == nil || sigS == nil {
		return nil, errors.New("invalid TXT signature")
	}

	if !ecdsa.Verify(pubKey, []byte(encodedVal), sigR, sigS) {
		return nil, errors.New("invalid signature")
	}

	val, _ := hex.DecodeString(encodedVal)
	addrs := strings.Split(string(val), ",")
	ret := make([]r.Peer, len(addrs))
	for i := range ret {
		ret[i] = r.TCPPeer{Addr: addrs[i]}
	}
	return ret, nil
}

func query(name string, resolver string, timeout time.Duration, pubKey *ecdsa.PublicKey, result chan<- []r.Peer, quit <-chan bool) {
	var msg *dns.Msg
	var data []byte
	var err error
	var conn net.Conn
	var fin chan bool

	msg = new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeTXT)

	ret := make(chan []r.Peer, 1)
	conn, err = net.DialTimeout("udp", resolver, timeout)
	if err != nil {
		log.Printf("fail to connect %s with UDP: %s", resolver, err)
		ret <- nil
		goto waiting
	}

	data, err = msg.Pack()
	if err != nil {
		ret <- nil
		goto waiting
	}

	// receiver uses this channel to notify sender to quit
	fin = make(chan bool)

	// receiver
	go func() {
		var buf [65536]byte
		// quit only if a valid response received or conn has closed by sender
		// recvLoop:
		for {
			n, e := conn.Read(buf[:])
			if e != nil {
				ret <- nil
				break
			}
			endpoints, e := parseAndVerify(buf[:n], pubKey)
			if e != nil {
				log.Printf("fail to parse and verify response: %s", e)
				continue
			}
			ret <- endpoints
			break
		}
		close(fin)
	}()

	// sender
	go func() {
		// when quit, close conn so receiver knows to quit as well
		defer conn.Close()

		// retry 3 times, timeout initially 2 seconds, double for each retry
		// receiver will close fin channel to notify sender that job has done
		gt := time.NewTimer(timeout)
		for to, retry := 2*time.Second, 3; retry > 0; to, retry = to*2, retry-1 {
			_, err := conn.Write(data)
			if err != nil {
				return
			}
			t := time.NewTimer(to)
			select {
			case <-fin:
				t.Stop()
				gt.Stop()
				return
			case <-t.C:
				continue
			case <-gt.C:
				t.Stop()
				return
			}
		}
		// after all retries, continue waiting for receiver or overall timeout
		select {
		case <-fin:
		case <-gt.C:
		}
		return
	}()

	// always close conn when quit, so sender and receiver get to know
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

waiting:
	select {
	case endpoints := <-ret:
		select {
		case <-quit:
		case result <- endpoints:
		}
	case <-quit:
	}
}

func (c *Client) Query(name string, timeout time.Duration) []r.Peer {
	// spawn query goroutines for each resolver, returns the first valid result,
	// use a channel to notify the rest to quit.
	quit := make(chan bool)
	defer close(quit)
	result := make(chan []r.Peer)

	for _, resolver := range c.Resolvers {
		go query(name, resolver, timeout, c.PubKey, result, quit)
	}

	cnt := 0
	var ret []r.Peer
loop:
	for ret = range result {
		if ret != nil {
			break loop
		} else {
			cnt++
			if cnt == len(c.Resolvers) {
				// all resolvers failed
				break loop
			}
		}
	}
	return ret
}

// simple implementation, missing a number of DNS features like DNSSEC, EDNS0
type Server struct {
	Net     []string
	Addr    string
	Timeout time.Duration

	prvKey *ecdsa.PrivateKey
	data   map[string][3]string
	lock   *sync.RWMutex

	udp *net.UDPConn
	tcp *net.TCPListener
}

func readRequest(conn net.Conn, timeout time.Duration) (*dns.Msg, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	c := &dns.Conn{Conn: conn, TsigSecret: make(map[string]string)}
	return c.ReadMsg()
}

func (svr *Server) handleRequest(req *dns.Msg) (*dns.Msg, bool) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.MsgHdr.Authoritative = true

	if len(req.Question) <= 0 || req.Question[0].Qtype != dns.TypeTXT {
		log.Printf("I am not supposed to answer this request")
		resp.MsgHdr.Rcode = dns.RcodeRefused
		return resp, false
	}

	// reader critical section
	svr.lock.RLock()
	v, ok := svr.data[req.Question[0].Name]
	svr.lock.RUnlock()

	if !ok {
		resp.MsgHdr.Rcode = dns.RcodeNameError
		return resp, false
	}

	t := new(dns.TXT)
	t.Hdr = dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		Ttl:    5,
	}
	t.Txt = []string{v[0], v[1], v[2]}
	resp.Answer = append(resp.Answer, t)
	return resp, true
}

func (svr *Server) serveUDP() error {
	var buf [65536]byte
	for {
		n, addr, err := svr.udp.ReadFromUDP(buf[:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			} else {
				return err
			}
		}
		log.Printf("%d bytes data received from %s", n, addr)
		req := new(dns.Msg)
		err = req.Unpack(buf[:n])
		if err != nil {
			log.Printf("invalid DNS request: %s", err)
			continue
		}
		resp, _ := svr.handleRequest(req)
		data, err := resp.Pack()
		if err != nil {
			log.Printf("fail to pack DNS response")
			continue
		}
		// should answer with truncated response if too large
		svr.udp.WriteToUDP(data, addr)
	}
}

func (svr *Server) serveTCP() error {
	for {
		var tempDelay time.Duration
		conn, e := svr.tcp.AcceptTCP()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			} else {
				return e
			}
		}
		// process single connection
		go func(c *net.TCPConn) {
			var buf [dns.MaxMsgSize + 2]byte
			for {
				req, err := readRequest(c, svr.Timeout)
				if err != nil {
					c.Close()
					return
				}
				resp, ok := svr.handleRequest(req)
				data, err := resp.Pack()
				if err != nil {
					log.Printf("fail to pack DNS response")
					c.Close()
					return
				}
				if len(data) > dns.MaxMsgSize {
					c.Close()
					return
				}
				copy(buf[2:], data)
				binary.BigEndian.PutUint16(buf[:], uint16(len(data)))
				c.Write(buf[:len(data)+2])
				if !ok {
					c.Close()
					return
				}
			}
		}(conn)
	}
}

func (svr *Server) ListenAndServe() error {
	runnable := 0
	// listen
	for _, proto := range svr.Net {
		switch proto {
		case "tcp", "tcp4", "tcp6":
			log.Printf("start TCP server ...")
			tcpAddr, err := net.ResolveTCPAddr(proto, svr.Addr)
			if err != nil {
				log.Printf("fail to resolve address: %s", err)
				return err
			}
			svr.tcp, err = net.ListenTCP(proto, tcpAddr)
			if err != nil {
				log.Printf("fail to listen on address: %s", err)
				return err
			}
			log.Printf("TCP server listens on %s", tcpAddr)
			runnable++
		case "udp", "udp4", "udp6":
			log.Printf("start UDP server ...")
			udpAddr, err := net.ResolveUDPAddr(proto, svr.Addr)
			if err != nil {
				return err
			}
			svr.udp, err = net.ListenUDP(proto, udpAddr)
			if err != nil {
				return err
			}
			log.Printf("UDP server listens on %s", udpAddr)
			runnable++
		}
	}

	// serve
	if runnable == 0 {
		return nil
	} else if runnable == 1 {
		if svr.udp != nil {
			return svr.serveUDP()
		}
		return svr.serveTCP()
	} else {
		go svr.serveUDP()
		return svr.serveTCP()
	}
}

func (svr *Server) Update(k string, v string) {
	v = hex.EncodeToString([]byte(v))
	r, s, err := ecdsa.Sign(rand.Reader, svr.prvKey, []byte(v))
	if err != nil {
		log.Printf("error to sign data %s:%s", k, v)
		return
	}
	svr.lock.Lock()
	if !strings.HasSuffix(k, ".") {
		k = k + "."
	}
	svr.data[k] = [3]string{v, hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes())}
	svr.lock.Unlock()
}

func (svr *Server) ReloadData(rawData map[string]string) {
	data := make(map[string][3]string)
	// generate
	for k, v := range rawData {
		v = hex.EncodeToString([]byte(v))
		r, s, err := ecdsa.Sign(rand.Reader, svr.prvKey, []byte(v))
		if err != nil {
			log.Printf("error to sign data %s:%s", k, v)
			continue
		}
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		data[k] = [3]string{v, hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes())}
	}

	// replace
	svr.lock.Lock()
	svr.data = data
	svr.lock.Unlock()
}

func (svr *Server) Close() {
	if svr.udp != nil {
		svr.udp.Close()
	}
	if svr.tcp != nil {
		svr.tcp.Close()
	}
}

func NewServer(prvKey *ecdsa.PrivateKey, rawData map[string]string) *Server {
	data := make(map[string][3]string)
	for k, v := range rawData {
		v = hex.EncodeToString([]byte(v))
		r, s, err := ecdsa.Sign(rand.Reader, prvKey, []byte(v))
		if err != nil {
			log.Printf("error to sign data %s:%s", k, v)
			continue
		}
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		data[k] = [3]string{v, hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes())}
	}

	return &Server{
		Addr:    ":53",
		Net:     []string{"tcp", "udp"},
		Timeout: 2 * time.Minute,
		prvKey:  prvKey,
		data:    data,
		lock:    &sync.RWMutex{},
	}
}
