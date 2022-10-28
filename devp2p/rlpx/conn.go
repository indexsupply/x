package rlpx

import (
	"net"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/indexsupply/x/enr"
)

// Represents an RLPX connection which wraps a TCPConn to the
// remote and contains state management of the handshake.
type Conn struct {
	h       *handshake
	tcpConn *net.TCPConn
}

func Dial(pk *secp256k1.PrivateKey, to *enr.Record) (*Conn, error) {
	tcp, err := net.DialTCP("tcp", nil, to.TCPAddr())
	if err != nil {
		return nil, err
	}
	h, err := newHandshake(pk, to)
	return &Conn{h: h, tcpConn: tcp}, err
}
