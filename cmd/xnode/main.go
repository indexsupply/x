package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/indexsupply/x/enr"
	"github.com/indexsupply/x/rlpx"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

type errRW struct {
	c   net.Conn
	b   [1 << 14]byte //16 MiB devp2p max. TODO(ryan): use dynamic buffer
	err error
}

func (rw *errRW) Read(f func([]byte) error) {
	if rw.err != nil {
		return
	}
	var n int
	n, rw.err = rw.c.Read(rw.b[:])
	if rw.err != nil {
		return
	}
	rw.err = f(rw.b[:n])
}

func (rw *errRW) Write(f func() ([]byte, error)) {
	if rw.err != nil {
		return
	}
	var b []byte
	b, rw.err = f()
	if rw.err != nil {
		return
	}
	_, rw.err = rw.c.Write(b)
}

func serve(c net.Conn, node *enr.Record) {
	defer c.Close()
	hs := rlpx.Recipient(node.PrivateKey)
	rw := errRW{c: c}
	rw.Read(hs.HandleAuth)
	rw.Write(hs.Ack)
	rs, err := rlpx.Session(node, hs)
	check(err)
	rw.Read(rs.HandleHello)
	rw.Write(rs.Hello)
	if rw.err != nil {
		fmt.Printf("serve-error: %s\n", rw.err)
	}
}

func main() {
	var remoteURL string
	flag.StringVar(&remoteURL, "remote", "", "enode://XXX@host:port")
	flag.Parse()

	self := new(enr.Record)
	self.PrivateKey, _ = secp256k1.GeneratePrivateKey()
	self.PublicKey = self.PrivateKey.PubKey()
	self.Ip = net.ParseIP("127.0.0.1")
	self.TcpPort = 30303
	self.UdpPort = 30303

	remote := new(enr.Record)
	remote.PrivateKey, _ = secp256k1.GeneratePrivateKey()
	remote.PublicKey = remote.PrivateKey.PubKey()
	remote.Ip = net.ParseIP("127.0.0.1")
	remote.TcpPort = 30304
	remote.UdpPort = 30304

	if remoteURL != "" {
		var err error
		remote, err = enr.ParseV4(remoteURL)
		check(err)
	} else {
		listening := make(chan struct{}, 1)
		go func() {
			ln, err := net.Listen("tcp", remote.TCPAddr().String())
			check(err)
			listening <- struct{}{}
			for {
				conn, err := ln.Accept()
				check(err)
				go serve(conn, remote)

			}
		}()
		<-listening
	}

	conn, err := net.Dial("tcp", remote.TCPAddr().String())
	check(err)
	hs := rlpx.Initiator(self.PrivateKey, remote.PublicKey)
	rw := errRW{c: conn}
	rw.Write(hs.Auth)
	rw.Read(hs.HandleAck)
	check(rw.err)

	rs, err := rlpx.Session(self, hs)
	check(err)
	rs.Verbose = true

	rw.Write(rs.Hello)
	rw.Read(rs.HandleHello)
	rw.Write(rs.Status)
	check(rw.err)
	go rs.Listen(conn)
	select {}
}
