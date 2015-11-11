package rendezvous

import (
	"net"
	"time"
)

// these two interfaces are designed to unify the structure of two essential
// steps: 1) get one or more peers through a name; 2) connect to the
// peer to establish a channel
type Rendezvousor interface {
	Query(name string, timout time.Duration) []Peer
}

type Peer interface {
	Connect(time.Duration) (net.Conn, error)
}

// basic Internet address for TCP connection
type TCPPeer struct {
	Addr string
}

func (p TCPPeer) Connect(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", p.Addr, timeout)
}
