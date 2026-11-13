//go:build ignore

// A minimal WebSocket echo server for python_tests/test_websocket_*.py.
//
//   go run python_tests/fixtures/ws_echo_server.go -addr 127.0.0.1:18841
//
// Standard library only, on purpose: pulling github.com/gorilla/websocket into
// the module for a test fixture would put a second WebSocket implementation
// into the dependency graph of a project whose whole point is one exact
// implementation.  RFC 6455 framing is ~150 lines and the tests need exactly
// two things from it -- a handshake and echoed frames.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// readFrame returns one complete message, reassembling continuation frames.
func readFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	var assembled []byte
	first := true
	for {
		var hdr [2]byte
		if _, err = io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, err
		}
		fin := hdr[0]&0x80 != 0
		op := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		length := int(hdr[1] & 0x7f)

		switch length {
		case 126:
			var ext [2]byte
			if _, err = io.ReadFull(r, ext[:]); err != nil {
				return 0, nil, err
			}
			length = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err = io.ReadFull(r, ext[:]); err != nil {
				return 0, nil, err
			}
			length = int(binary.BigEndian.Uint64(ext[:]))
		}

		var mask [4]byte
		if masked {
			if _, err = io.ReadFull(r, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		data := make([]byte, length)
		if _, err = io.ReadFull(r, data); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range data {
				data[i] ^= mask[i&3]
			}
		}

		switch op {
		case 0x8: // close
			return 0x8, data, nil
		case 0x9, 0xA: // ping/pong: echo them back as the same opcode
			return op, data, nil
		}

		if first {
			opcode = op
			first = false
		}
		assembled = append(assembled, data...)
		if fin {
			return opcode, assembled, nil
		}
	}
}

func writeFrame(w io.Writer, opcode byte, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) <= 0xffff:
		hdr = append(hdr, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		hdr = append(hdr, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		hdr = append(hdr, ext[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// echoConn upgrades one HTTP request and echoes frames until the peer closes.
func echoConn(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "expected a websocket upgrade", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n"
	// Echo permessage-deflate only when the client offered it, so the
	// compression test can observe the negotiation.
	if strings.Contains(strings.ToLower(r.Header.Get("Sec-WebSocket-Extensions")), "permessage-deflate") {
		resp += "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
	}
	resp += "\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	reader := bufio.NewReader(rw.Reader)
	for {
		opcode, payload, err := readFrame(reader)
		if err != nil {
			return
		}
		if opcode == 0x8 {
			_ = writeFrame(conn, 0x8, payload)
			return
		}
		if err := writeFrame(conn, opcode, payload); err != nil {
			return
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18841", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(echoConn)}
	fmt.Printf("ws echo server on %s\n", *addr)
	log.Fatal(srv.Serve(ln))
}
