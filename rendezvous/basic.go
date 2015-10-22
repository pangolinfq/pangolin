package rendezvous

import (
	"net"
	"time"
)

// this two interfaces are designed to unify the structure of two essential
// steps: 1) get one or more addresses through a name; 2) connect to the
// address to establish a channel
type Rendezvousor interface {
	Query(name string, timout time.Duration) []Peer
}

type Peer interface {
	Connect(time.Duration) (net.Conn, error)
}

// basic Internet address for TCP connection
type NetAddrPeer struct {
	Addr string
}

func (p NetAddrPeer) Connect(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", p.Addr, timeout)
}
