package main

import (
	"github.com/yinghuocho/gosocks"
	"log"
	"strings"
	"time"
)

type forwardingHandler struct {
	basic            *gosocks.BasicSocksHandler
	tunnelAddr       string
	tunnelingDomains map[string]bool
}

type socksForwarder interface {
	forwardTCP(*gosocks.SocksRequest, *gosocks.SocksConn)
}

type socks2SocksForwarder struct {
	socksDialer *gosocks.SocksDialer
	socksAddr   string
}

func (sf *socks2SocksForwarder) forwardTCP(req *gosocks.SocksRequest, src *gosocks.SocksConn) {
	dst, err := sf.socksDialer.Dial(sf.socksAddr)
	if err != nil {
		gosocks.WriteSocksReply(src, &gosocks.SocksReply{
			gosocks.SocksGeneralFailure, gosocks.SocksIPv4Host, "0.0.0.0", 0})
		src.Close()
		return
	}
	gosocks.WriteSocksRequest(dst, req)
	gosocks.CopyLoopTimeout(src, dst, src.Timeout)
}

func (f *forwardingHandler) lookup(req *gosocks.SocksRequest, conn *gosocks.SocksConn) socksForwarder {
	if f.tunnelingDomains == nil {
		return nil
	}
	// (sub)domain matching with tunneling domains
	labels := strings.Split(req.DstHost, ".")
	for i := 0; i < len(labels); i++ {
		_, ok := f.tunnelingDomains[strings.Join(labels[i:], ".")]
		if ok {
			return &socks2SocksForwarder{
				socksDialer: &gosocks.SocksDialer{
					Timeout: conn.Timeout,
					Auth:    &gosocks.AnonymousClientAuthenticator{},
				},
				socksAddr: f.tunnelAddr,
			}
		}
	}
	return nil
}

func (f *forwardingHandler) ServeSocks(conn *gosocks.SocksConn) {
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	req, err := gosocks.ReadSocksRequest(conn)
	if err != nil {
		log.Printf("error in ReadSocksRequest: %s", err)
		return
	}

	switch req.Cmd {
	case gosocks.SocksCmdConnect:
		forwarder := f.lookup(&req, conn)
		if forwarder != nil {
			forwarder.forwardTCP(&req, conn)
		} else {
			f.basic.HandleCmdConnect(&req, conn)
		}
		return
	case gosocks.SocksCmdUDPAssociate:
		f.basic.HandleCmdUDPAssociate(&req, conn)
		return
	case gosocks.SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}
