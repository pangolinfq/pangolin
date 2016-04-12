package main

import (
	"log"
	"strings"
	"time"

	"github.com/yinghuocho/golibfq/chain"
	"github.com/yinghuocho/gosocks"
)

type forwardingHandler struct {
	basic            *gosocks.BasicSocksHandler
	tunnelAddr       string
	tunnelingDomains map[string]bool
	tunnelingAll     bool
}

func (f *forwardingHandler) lookup(dst string, conn *gosocks.SocksConn) chain.SocksChain {
	// forward all connections through tunnel if tunnelingAll flag is on, or
	// something wrong with loading tunnelingDomains,
	if f.tunnelingAll || f.tunnelingDomains == nil {
		return &chain.SocksSocksChain{
			SocksDialer: &gosocks.SocksDialer{
				Timeout: conn.Timeout,
				Auth:    &gosocks.AnonymousClientAuthenticator{},
			},
			SocksAddr: f.tunnelAddr,
		}
	}

	// (sub)domain matching with tunneling domains
	labels := strings.Split(dst, ".")
	for i := 0; i < len(labels); i++ {
		_, ok := f.tunnelingDomains[strings.Join(labels[i:], ".")]
		if ok {
			return &chain.SocksSocksChain{
				SocksDialer: &gosocks.SocksDialer{
					Timeout: conn.Timeout,
					Auth:    &gosocks.AnonymousClientAuthenticator{},
				},
				SocksAddr: f.tunnelAddr,
			}
		}
	}
	return nil
}

func (f *forwardingHandler) handleUDPAssociate(req *gosocks.SocksRequest, conn *gosocks.SocksConn) {
	clientBind, clientAssociate, udpReq, clientAddr, err := f.basic.UDPAssociateFirstPacket(req, conn)
	if err != nil {
		conn.Close()
		return
	}
	chain := f.lookup(udpReq.DstHost, conn)
	if chain != nil {
		chain.UDPAssociate(req, conn, clientBind, clientAssociate, udpReq, clientAddr)
	} else {
		f.basic.UDPAssociateForwarding(conn, clientBind, clientAssociate, udpReq, clientAddr)
	}
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
		chain := f.lookup(req.DstHost, conn)
		if chain != nil {
			chain.TCP(req, conn)
		} else {
			f.basic.HandleCmdConnect(req, conn)
		}
		return
	case gosocks.SocksCmdUDPAssociate:
		f.handleUDPAssociate(req, conn)
		return
	case gosocks.SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}

func (f *forwardingHandler) Quit() {}
