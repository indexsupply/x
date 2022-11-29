// Implements the RLPx protocol. Code is based off the devp2p spec defined here:
// https://github.com/ethereum/devp2p/blob/master/rlpx.md
package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	mrand "math/rand"
	"net"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"

	"github.com/indexsupply/x/bint"
	"github.com/indexsupply/x/ecies"
	"github.com/indexsupply/x/enr"
	"github.com/indexsupply/x/isxerrors"
	"github.com/indexsupply/x/isxhash"
	"github.com/indexsupply/x/isxsecp256k1"
	"github.com/indexsupply/x/rlp"
)

type session struct {
	Verbose bool

	conn   net.Conn
	local  *enr.Record
	ig, eg *mstate
}

func (s *session) log(format string, args ...any) {
	if s.Verbose {
		fmt.Printf(format, args...)
	}
}

func Session(l *enr.Record, hs *handshake) (*session, error) {
	err := hs.complete()
	if err != nil {
		return nil, err
	}
	s := &session{local: l}

	//static-shared-secret = ecdh.agree(privkey, remote-pubk)
	//ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
	//shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
	//aes-secret = keccak256(ephemeral-key || shared-secret)
	//mac-secret = keccak256(ephemeral-key || aes-secret)
	ephKey := secp256k1.GenerateSharedSecret(
		hs.localEphPrvKey,
		hs.remoteEphPubKey,
	)
	sharedSecret := isxhash.Keccak(append(
		ephKey,
		isxhash.Keccak(append(
			hs.recipientNonce[:],
			hs.initNonce[:]...,
		))...,
	))
	aesSecret := isxhash.Keccak(append(ephKey, sharedSecret...))
	macSecret := isxhash.Keccak(append(ephKey, aesSecret...))

	s.ig, err = newmstate(aesSecret, macSecret)
	if err != nil {
		return nil, err
	}
	s.eg, err = newmstate(aesSecret, macSecret)
	if err != nil {
		return nil, err
	}

	var inonce, rnonce [32]byte
	for i := 0; i < 32; i++ {
		inonce[i] = macSecret[i] ^ hs.initNonce[i]
		rnonce[i] = macSecret[i] ^ hs.recipientNonce[i]
	}

	if hs.initiator {
		//egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
		//ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
		s.eg.hash.Write(rnonce[:])
		s.eg.hash.Write(hs.auth)
		s.ig.hash.Write(inonce[:])
		s.ig.hash.Write(hs.ack)
	} else {
		//egress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
		//ingress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
		s.eg.hash.Write(inonce[:])
		s.eg.hash.Write(hs.ack)
		s.ig.hash.Write(rnonce[:])
		s.ig.hash.Write(hs.auth)
	}
	return s, nil
}

type mstate struct {
	block  cipher.Block
	hash   hash.Hash
	stream cipher.Stream
}

func newmstate(aesSecret, macSecret []byte) (*mstate, error) {
	eb, err := aes.NewCipher(aesSecret)
	if err != nil {
		return nil, err
	}
	es := cipher.NewCTR(eb, make([]byte, 16))

	mb, err := aes.NewCipher(macSecret)
	if err != nil {
		return nil, err
	}
	h := sha3.NewLegacyKeccak256()
	return &mstate{
		hash:   h,
		block:  mb,
		stream: es,
	}, nil
}

// updates hash using the following devp2p construction:
//
// header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
// egress-mac = keccak256.update(egress-mac, header-mac-seed)
// header-mac = keccak256.digest(egress-mac)[:16]
func (ms *mstate) header(h []byte) []byte {
	prev := ms.hash.Sum(nil)
	dest := make([]byte, 16)
	ms.block.Encrypt(dest, prev[:16])
	for i := range dest {
		dest[i] ^= h[i]
	}
	ms.hash.Write(dest)
	return ms.hash.Sum(nil)[:16]
}

// updates hash using the following devp2p construction:
//
// egress-mac = keccak256.update(egress-mac, frame-ciphertext)
// frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
// egress-mac = keccak256.update(egress-mac, frame-mac-seed)
// frame-mac = keccak256.digest(egress-mac)[:16]
func (ms *mstate) frame(fct []byte) []byte {
	ms.hash.Write(fct)
	prev := ms.hash.Sum(nil)
	dest := make([]byte, 16)
	ms.block.Encrypt(dest, prev[:16])
	for i := range dest {
		dest[i] ^= prev[i]
	}
	ms.hash.Write(dest)
	return ms.hash.Sum(nil)[:16]
}

func (s *session) unframe(buf []byte) (byte, []byte, error) {
	if len(buf) < 32 {
		return 0, nil, errors.New("buf too small for 32byte header")
	}
	if !hmac.Equal(s.ig.header(buf[:16]), buf[16:32]) {
		return 0, nil, errors.New("invalid header mac")
	}
	s.ig.stream.XORKeyStream(buf[:16], buf[:16])
	var (
		frameSize = bint.Decode(buf[:3])
		frameEnd  = 32 + frameSize + (16 - frameSize%16)
		frame     = buf[32:frameEnd]
		frameMac  = buf[frameEnd : frameEnd+16]
	)
	if !hmac.Equal(s.ig.frame(frame), frameMac) {
		return 0, nil, errors.New("invalid frame mac")
	}
	s.ig.stream.XORKeyStream(frame, frame)
	return frame[0:1][0], frame[1:frameSize], nil
}

// Encodees data into an RLPx frame
//
// frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
// header-ciphertext = aes(aes-secret, header)
// header = frame-size || header-data || header-padding
// header-data = [capability-id, context-id]
// capability-id = integer, always zero
// context-id = integer, always zero
// header-padding = zero-fill header to 16-byte boundary
// frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
// frame-padding = zero-fill frame-data to 16-byte boundary
func (s *session) frame(msgID byte, msgData []byte) []byte {
	// Per the spec, the header contains: size, data, and padding.
	// However, the data (eg [capability-id, context-id]) is unused.
	// Therefore, we leave the header-data as a list of zero bytes.
	// Padding is addressed by pre-allocating a 16 byte header.
	header := make([]byte, 16)
	bint.Encode(header[:3], uint64(len(msgData)+1)) //include id
	s.eg.stream.XORKeyStream(header, header)

	msgData = append(rlp.Encode(rlp.Byte(msgID)), msgData...)
	padding := 16 - len(msgData)%16
	if padding != 0 {
		msgData = append(msgData, make([]byte, padding)...)
	}
	s.eg.stream.XORKeyStream(msgData, msgData)

	var frame []byte
	frame = append(frame, header...)
	frame = append(frame, s.eg.header(header)...)
	frame = append(frame, msgData...)
	frame = append(frame, s.eg.frame(msgData)...)
	return frame
}

func (s *session) encode(msgID byte, item rlp.Item) []byte {
	return frame(msgID, snappy.Encode(nil, rlp.Encode(item)))
}

func (s *session) decode(d []byte) (byte, rlp.Item, error) {
	msgID, c, err := unframe(d)
	if err != nil {
		return 0, nil, isxerrors.Errorf("unframing msg: %w", err)
	}
	uc, err := snappy.Decode(nil, c)
	if err != nil {
		return 0, nil, isxerrors.Errorf("decompressing msg data: %w", err)
	}
	item, err := rlp.Decode(uc)
	if err != nil {
		return 0, nil, isxerrors.Errorf("decoding msg into an rlp item: %w", err)
	}
	return msgID, item, nil
}

type handshake struct {
	initiator bool

	localPrvKey, localEphPrvKey   *secp256k1.PrivateKey
	remotePubKey, remoteEphPubKey *secp256k1.PublicKey

	initNonce, recipientNonce [32]byte

	// store results for session initialization
	auth, ack []byte
}

func (h *handshake) complete() error {
	if h.initNonce == [32]byte{} {
		return errors.New("missing init nonce")
	}
	if h.recipientNonce == [32]byte{} {
		return errors.New("missing recipient nonce")
	}
	if h.remotePubKey == nil {
		return errors.New("missing remote public key")
	}
	if h.remoteEphPubKey == nil {
		return errors.New("missing remote eph public key")
	}
	return nil
}

func Initiator(l *secp256k1.PrivateKey, r *secp256k1.PublicKey) *handshake {
	return &handshake{
		initiator:    true,
		localPrvKey:  l,
		remotePubKey: r,
	}
}

func Recipient(l *secp256k1.PrivateKey) *handshake {
	return &handshake{
		initiator:   false,
		localPrvKey: l,
	}
}

// Assembles an Auth message according to the following:
//
// auth = auth-size || enc-auth-body
// auth-size = size of enc-auth-body, encoded as a big-endian 16-bit integer
// auth-vsn = 4
// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
// shared-secret = ecdh.agree(privkey, remote-pubk)
// sig = secp256k1.sign(ephemeral-privkey , shared-secret ^ initiator-nonce)
// enc-auth-body = ecies.encrypt(recipient-pubk, auth-body || auth-padding, auth-size)
// auth-padding = arbitrary data
func (h *handshake) Auth() ([]byte, error) {
	_, err := rand.Read(h.initNonce[:])
	if err != nil {
		return nil, err
	}
	h.localEphPrvKey, err = secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	var (
		ss = secp256k1.GenerateSharedSecret(h.localPrvKey, h.remotePubKey)
		b  [32]byte
	)
	for i := 0; i < 32; i++ {
		b[i] = ss[i] ^ h.initNonce[i]
	}
	sig, err := isxsecp256k1.Sign(h.localEphPrvKey, b)
	if err != nil {
		return nil, err
	}
	const authVersion = 4
	authBody := rlp.Encode(rlp.List(
		rlp.Bytes(sig[:]),
		rlp.Secp256k1PublicKey(h.localPrvKey.PubKey()),
		rlp.Bytes(h.initNonce[:]),
		rlp.Int(authVersion),
	))
	authBody = append(authBody, make([]byte, mrand.Intn(100)+100)...)

	var authSize [2]byte
	bint.Encode(authSize[:], uint64(len(authBody)+ecies.Overhead))
	encAuthBody, err := ecies.Encrypt(h.remotePubKey, authBody, authSize[:])
	if err != nil {
		return nil, err
	}

	h.auth = append(authSize[:], encAuthBody...)
	return h.auth, nil
}

func (h *handshake) HandleAuth(d []byte) error {
	h.auth = d
	if len(d) <= 2+ecies.Overhead {
		return errors.New("message must be at least 2 + ecies overhead bytes long")
	}
	size := bint.Decode(d[:2])
	authBody, err := ecies.Decrypt(h.localPrvKey, d[2:2+size], d[:2])
	if err != nil {
		return isxerrors.Errorf("decrypting auth: %w", err)
	}
	authItem, err := rlp.Decode(authBody)
	if err != nil {
		return err
	}

	sig, err := authItem.At(0).Bytes65()
	if err != nil {
		return err
	}
	h.remotePubKey, err = authItem.At(1).Secp256k1PublicKey()
	if err != nil {
		return err
	}
	h.initNonce, err = authItem.At(2).Bytes32()
	if err != nil {
		return err
	}
	var (
		ss = secp256k1.GenerateSharedSecret(h.localPrvKey, h.remotePubKey)
		b  [32]byte
	)
	for i := 0; i < 32; i++ {
		b[i] = ss[i] ^ h.initNonce[i]
	}
	h.remoteEphPubKey, err = isxsecp256k1.Recover(sig, b)
	if err != nil {
		return err
	}
	return nil
}

// ack = ack-size || enc-ack-body
// ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
// ack-vsn = 4
// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
// enc-ack-body = ecies.encrypt(initiator-pubk, ack-body || ack-padding, ack-size)
// ack-padding = arbitrary data
func (h *handshake) Ack() ([]byte, error) {
	if h.initiator {
		return nil, errors.New("cannot send ack message when you are the initiator")
	}
	_, err := rand.Read(h.recipientNonce[:])
	if err != nil {
		return nil, err
	}
	h.localEphPrvKey, err = secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	const authVersion = 4
	ackBody := rlp.Encode(rlp.List(
		rlp.Secp256k1PublicKey(h.localEphPrvKey.PubKey()),
		rlp.Bytes(h.recipientNonce[:]),
		rlp.Int(authVersion),
	))
	ackBody = append(ackBody, make([]byte, mrand.Intn(100)+100)...)
	var ackSize [2]byte
	bint.Encode(ackSize[:], uint64(len(ackBody)+ecies.Overhead))
	encAckBody, err := ecies.Encrypt(h.remotePubKey, ackBody, ackSize[:])
	if err != nil {
		return nil, err
	}
	h.ack = append(ackSize[:], encAckBody...)
	return h.ack, nil
}

func (h *handshake) HandleAck(d []byte) error {
	h.ack = d
	if len(d) <= 2+ecies.Overhead {
		return errors.New("message must be at least 2 + ecies overhead bytes long")
	}
	size := bint.Decode(d[:2])
	ackBody, err := ecies.Decrypt(h.localPrvKey, d[2:2+size], d[:2])
	if err != nil {
		return isxerrors.Errorf("decrypting ack: %w", err)
	}
	ackItem, err := rlp.Decode(ackBody)
	if err != nil {
		return err
	}
	h.remoteEphPubKey, err = ackItem.At(0).Secp256k1PublicKey()
	if err != nil {
		return err
	}
	h.recipientNonce, err = ackItem.At(1).Bytes32()
	return err
}

func (s *session) Listen(c net.Conn) {
	buf := make([]byte, 1<<14)
	for {
		n, err := c.Read(buf)
		if err != nil {
			s.log("err-read: %s\n", err)
			return
		}
		err = s.handle(c, buf[:n])
		if err != nil {
			s.log("err-handle: %s\n", err)
		}
	}
}

const (
	hello = 0x00
	disc  = 0x01
	ping  = 0x02
	pong  = 0x03

	status          = 0x10
	newBlockhash    = 0x11
	getBlockHeaders = 0x13
	headersID       = 0x14
)

func (s *session) handle(c net.Conn, b []byte) error {
	id, item, err := s.decode(b)
	if err != nil {
		return isxerrors.Errorf("decoding frame: %w", err)
	}
	switch id {
	case hello:
	case disc:
		s.handleDisconnect(item)
	case ping:
		s.handlePing()
	case pong:
		s.log("<pong")
	case status:
		s.handleStatus(item)
	case getBlockHeaders:
		s.handleGetHeaders(item)
	default:
		fmt.Printf("un-handled id: %x\n", id)
	}
	return nil
}

func (s *session) Hello() ([]byte, error) {
	// hello is the only message that isn't compressed
	return s.encode(0x00, rlp.Encode(rlp.List(
		rlp.Int(5),
		rlp.String("indexsupply/0"),
		rlp.List(
			rlp.List(rlp.String("p2p"), rlp.Int(5)),
			rlp.List(rlp.String("eth"), rlp.Int(67)),
		),
		rlp.Uint16(s.local.TcpPort),
		rlp.Secp256k1PublicKey(s.local.PublicKey),
	))), nil
}

func (s *session) HandleHello(d []byte) error {
	// hello is the only message that isn't compressed
	_, b, err := s.unframe(d)
	if err != nil {
		return isxerrors.Errorf("decoding hello frame: %w", err)
	}
	item, err := rlp.Decode(b)
	if err != nil {
		return isxerrors.Errorf("decoding rlp: %w", err)
	}
	id, err := item.At(1).String()
	if err != nil {
		return isxerrors.Errorf("reading id: %w", err)
	}
	s.log("hello from %s\n", id)
	return nil
}

func (s *session) handlePing() {
	s.conn.Write(s.encode(pong, rlp.List()))
}

func (s *session) handleDisconnect(item rlp.Item) {
	defer s.conn.Close()
	b, _ := item.Bytes()
	s.log("disconnect reason: %x\n", b)
}

func (s *session) handleGetHeaders(item rlp.Item) uint64 {
	reqID, _ := item.At(0).Uint64()
	headers := s.encode(0x14, rlp.List(
		rlp.Uint64(reqID),
		rlp.List(),
	))
	s.log("<get-headers: %d\n", reqID)
	s.conn.Write(headers)
}

func (s *session) handleStatus(item rlp.Item) {
	bh, _ := item.At(3).Bytes()
	s.log("status: %x\n", bh)
}

func (s *session) Status() ([]byte, error) {
	g, _ := hex.DecodeString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	f, _ := hex.DecodeString("fc64ec04")
	return s.encode(0x10, rlp.List(
		rlp.Int(67),
		rlp.Int(1),
		rlp.Int(17179869184),
		rlp.Bytes(g[:]),
		rlp.Bytes(g[:]),
		rlp.List(rlp.Bytes(f), rlp.Int(1150000)),
	)), nil
}
