package gui

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "not a websocket upgrade", 400)
		return nil, errors.New("not websocket")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", 400)
		return nil, errors.New("missing key")
	}

	accept := computeAccept(key)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", 500)
		return nil, errors.New("hijack not supported")
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	)
	if _, err := fmt.Fprint(buf, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func computeAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsWriteText(conn net.Conn, data []byte) error {
	length := len(data)
	var header []byte
	header = append(header, 0x81)

	if length <= 125 {
		header = append(header, byte(length))
	} else if length <= 65535 {
		header = append(header, 126)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(length))
		header = append(header, b...)
	} else {
		header = append(header, 127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(length))
		header = append(header, b...)
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}
