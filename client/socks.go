package main

import (
	"github.com/yinghuocho/gosocks"
	"log"
	"net"
	"strings"
	"time"
)

type forwardingHandler struct {
	basic            *gosocks.BasicSocksHandler
	tunnelAddr       string
	tunnelingDomains map[string]bool
	tunnelingAll     bool
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
		gosocks.ReplyGeneralFailure(src, req)
		src.Close()
		return
	}
	gosocks.WriteSocksRequest(dst, req)
	gosocks.CopyLoopTimeout(src, dst, src.Timeout)
}

func (f *forwardingHandler) lookup(req *gosocks.SocksRequest, conn *gosocks.SocksConn) socksForwarder {
	// forward all connections through tunnel if tunnelingAll flag is on, or
	// something wrong with loading tunnelingDomains,
	if f.tunnelingAll || f.tunnelingDomains == nil {
		return &socks2SocksForwarder{
			socksDialer: &gosocks.SocksDialer{
				Timeout: conn.Timeout,
				Auth:    &gosocks.AnonymousClientAuthenticator{},
			},
			socksAddr: f.tunnelAddr,
		}
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

func (f *forwardingHandler) handleUDPAssociate(req *gosocks.SocksRequest, conn *gosocks.SocksConn) {
	// bind local port
	socksAddr := conn.LocalAddr().(*net.TCPAddr)
	clientBind, err := net.ListenUDP("udp", &net.UDPAddr{IP: socksAddr.IP, Port: 0, Zone: socksAddr.Zone})
	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		gosocks.ReplyGeneralFailure(conn, req)
		conn.Close()
		return
	}

	bindAddr := clientBind.LocalAddr()
	hostType, host, port := gosocks.NetAddrToSocksAddr(bindAddr)
	log.Printf("UDP bind local address: %s", bindAddr.String())
	_, err = gosocks.WriteSocksReply(conn, &gosocks.SocksReply{
		Rep:      gosocks.SocksSucceeded,
		HostType: hostType,
		BndHost:  host,
		BndPort:  port,
	})
	if err != nil {
		log.Printf("error in sending reply: %s", err)
		conn.Close()
		return
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
