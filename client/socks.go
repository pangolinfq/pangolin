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
	forwardUDP(*gosocks.SocksRequest, *gosocks.SocksConn, *net.UDPConn, *net.UDPAddr, *gosocks.UDPRequest, *net.UDPAddr)
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

func (sf *socks2SocksForwarder) forwardUDP(req *gosocks.SocksRequest, src *gosocks.SocksConn, clientBind *net.UDPConn, clientAssociate *net.UDPAddr, firstPkt *gosocks.UDPRequest, clientAddr *net.UDPAddr) {
	dst, err := sf.socksDialer.Dial(sf.socksAddr)
	if err != nil {
		src.Close()
		clientBind.Close()
		return
	}

	// bind a UDP port for forwarding
	dstAddr := dst.LocalAddr().(*net.TCPAddr)
	relayBind, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   dstAddr.IP,
		Port: 0,
		Zone: dstAddr.Zone,
	})
	if err != nil {
		log.Printf("error in binding local UDP: %s", err)
		src.Close()
		dst.Close()
		clientBind.Close()
		return
	}

	// send request to forwarding socks connection
	hostType, host, port := gosocks.NetAddrToSocksAddr(relayBind.LocalAddr())
	_, err = gosocks.WriteSocksRequest(dst, &gosocks.SocksRequest{
		Cmd: req.Cmd, HostType: hostType, DstHost: host, DstPort: port})
	if err != nil {
		log.Printf("error in sending request to forwarding socks: %s", err)
		src.Close()
		dst.Close()
		clientBind.Close()
		relayBind.Close()
		return
	}

	// read reply from forwarding socks connection
	dst.SetDeadline(time.Now().Add(dst.Timeout))
	reply, err := gosocks.ReadSocksReply(dst)
	if err != nil {
		log.Printf("error in reading reply from forwarding socks: %s", err)
		src.Close()
		dst.Close()
		clientBind.Close()
		relayBind.Close()
		return
	}
	if reply.Rep != gosocks.SocksSucceeded {
		log.Printf("error in reply from forwarding socks: 0x%02x", reply.Rep)
		src.Close()
		dst.Close()
		clientBind.Close()
		relayBind.Close()
		return
	}

	// write first packet
	relayAddr := gosocks.SocksAddrToNetAddr("udp", reply.BndHost, reply.BndPort).(*net.UDPAddr)
	_, err = relayBind.WriteToUDP(gosocks.PackUDPRequest(firstPkt), relayAddr)
	if err != nil {
		log.Printf("error to send UDP packet to forwarding socks: %s", err)
		src.Close()
		dst.Close()
		clientBind.Close()
		relayBind.Close()
		return
	}

	// monitoring socks connections, quit for any reading event
	quit1 := make(chan bool)
	go gosocks.ConnMonitor(src, quit1)
	quit2 := make(chan bool)
	go gosocks.ConnMonitor(dst, quit2)

	// read client UPD packets
	chClientUDP := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(clientBind, chClientUDP)

	// read relay UPD packets
	chRelayUDP := make(chan *gosocks.UDPPacket)
	go gosocks.UDPReader(relayBind, chRelayUDP)

loop:
	for {
		t := time.NewTimer(src.Timeout)
		select {
		// packets from client, pack and send through tunnel
		case pkt, ok := <-chClientUDP:
			t.Stop()
			if !ok {
				break loop
			}
			// validation
			// 1) RFC1928 Section-7
			if !gosocks.LegalClientAddr(clientAssociate, pkt.Addr) {
				continue
			}
			// 2) format
			udpReq, err := gosocks.ParseUDPRequest(pkt.Data)
			if err != nil {
				log.Printf("error to parse UDP packet: %s", err)
				break loop
			}
			// 3) no fragment
			if udpReq.Frag != gosocks.SocksNoFragment {
				continue
			}

			clientAddr = pkt.Addr
			_, err = relayBind.WriteToUDP(gosocks.PackUDPRequest(firstPkt), relayAddr)
			if err != nil {
				log.Printf("error to relay UDP to forwarding socks: %s", err)
				break loop
			}

		// requests from forwarding socks, send to client
		case pkt, ok := <-chRelayUDP:
			t.Stop()
			if !ok {
				break loop
			}
			_, err := clientBind.WriteToUDP(pkt.Data, clientAddr)
			if err != nil {
				log.Printf("error to send UDP packet to client: %s", err)
				break loop
			}

		case <-quit1:
			t.Stop()
			log.Printf("UDP unexpected event from client socks")
			break loop

		case <-quit2:
			t.Stop()
			log.Printf("UDP unexpected event from forwarding socks")
			break loop

		case <-t.C:
			log.Printf("UDP timeout")
			break loop
		}
		t.Stop()
	}

	// clean up
	src.Close()
	dst.Close()
	clientBind.Close()
	relayBind.Close()
	<-chClientUDP
	<-chRelayUDP
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
	clientBind, clientAssociate, udpReq, clientAddr, err := f.basic.UDPAssociateFirstPacket(req, conn)
	if err != nil {
		conn.Close()
		return
	}
	forwarder := f.lookup(req, conn)
	if forwarder != nil {
		forwarder.forwardUDP(req, conn, clientBind, clientAssociate, udpReq, clientAddr)
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
		forwarder := f.lookup(req, conn)
		if forwarder != nil {
			forwarder.forwardTCP(req, conn)
		} else {
			f.basic.HandleCmdConnect(req, conn)
		}
		return
	case gosocks.SocksCmdUDPAssociate:
		f.basic.HandleCmdUDPAssociate(req, conn)
		return
	case gosocks.SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}
