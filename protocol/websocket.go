package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"myproxy/logging"
	"myproxy/readconfig"
	"net"
	"time"
)

const maxReadLength = 64 * 1024

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

// Track Websocket state
type WSStruct struct {
	// Websocket request
	Websocket bool

	// Websocket Connection
	WebsocketConn net.Conn
}

func WebsocketRead(request bool, conn net.Conn, timeOut int, sessionNo int64, buf []byte, mbuf []byte) (int, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var payloadLen int
	var dataLen int
	var offset int
	var opcode byte
	var fin bool
	var masked bool
	var maskKey [4]byte
	var rType string
	var maxPayloadLength int = readconfig.Config.WebSocket.MaxPayloadLength

	localBuf := make([]byte, maxPayloadLength+14)

	if request {
		rType = "Request"
	} else {
		rType = "Response"
	}

	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Connection: %s\n", rType, sessionNo, c2s(conn))

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
	// Read first 2 bytes of weboscket frame header
	n, err := conn.Read(localBuf[:2])
	if err != nil || n != 2 {
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d error: %v\n", rType, sessionNo, n, err)
		return 0, err
	}
	fin = localBuf[0]&0x80 != 0
	opcode = localBuf[0] & 0x0F
	masked = localBuf[1]&0x80 != 0
	payloadLen = int(localBuf[1] & 0x7F)
	offset = 2

	copy(mbuf[:], localBuf[:2])

	if payloadLen == 126 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		// Read 2 bytes for length
		n, err := conn.Read(localBuf[:2])
		if err != nil || n != 2 {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d error: %v\n", rType, sessionNo, n, err)
			return 0, err
		}
		payloadLen = int(binary.BigEndian.Uint16(localBuf[:2]))
		copy(mbuf[offset:], localBuf[:2])
		offset += 2
	} else if payloadLen == 127 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		// Read 8 bytes for length
		n, err := conn.Read(localBuf[:8])
		if err != nil || n != 8 {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d error: %v\n", rType, sessionNo, n, err)
			return 0, err
		}
		payloadLen = int(binary.BigEndian.Uint64(localBuf[:8]))
		copy(mbuf[offset:], localBuf[:8])
		offset += 8
	}
	if masked {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		// Read 4 bytes for mask
		n, err := conn.Read(localBuf[:4])
		if err != nil || n != 4 {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d error: %v\n", rType, sessionNo, n, err)
			return 0, err
		}
		copy(maskKey[:], localBuf[:4])
		copy(mbuf[offset:], localBuf[:4])
		offset += 4
	}

	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket Header: FIN %t Opcode: %d, Masked: %t Payload Length:%d Offset: %d\n", rType, sessionNo, fin, opcode, masked, payloadLen, offset)

	if payloadLen > maxPayloadLength {
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket payload length > max length %d>%d\n", rType, sessionNo, payloadLen, maxPayloadLength)
		return dataLen, errors.New("Payload too large")
	}

	dataLen = offset
	for dataLen < offset+payloadLen {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		start := time.Now()
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Start read\n", rType, sessionNo)
		n, err := conn.Read(localBuf[:offset+payloadLen-dataLen])
		elapsed := time.Since(start)
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read of %d bytes took %d milliseconds\n", rType, sessionNo, n, elapsed.Milliseconds())
		if err != nil || dataLen+n > offset+payloadLen {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d error: %v\n", rType, sessionNo, dataLen+n, err)
			return 0, err
		}
		copy(mbuf[dataLen:], localBuf[:n])
		dataLen = dataLen + n
	}
	copy(buf[:], mbuf[:])
	if masked {
		for i := 0; i < payloadLen; i++ {
			buf[offset+i] ^= maskKey[i%4]
		}
	}
	switch opcode {
	case 0x0: // continuation
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: continuation\n", rType, sessionNo)
	case 0x1: // Text frame
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: string\n", rType, sessionNo)
	case 0x2: // Binary frame
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: binary\n", rType, sessionNo)
	case 0x8: // Connection closed
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: close\n", rType, sessionNo)
		if !fin {
			logging.Printf("ERROR", "WebsocketRead%s: SessionID:%d Close with no FIN bit\n", rType, sessionNo)
		}
	case 0x9: // Ping
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: ping\n", rType, sessionNo)
		if !fin {
			logging.Printf("ERROR", "WebsocketRead%s: SessionID:%d Ping with no FIN bit\n", rType, sessionNo)
		}
	case 0xA: // Pong
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: pong\n", rType, sessionNo)
		if !fin {
			logging.Printf("ERROR", "WebsocketRead%s: SessionID:%d Pong with no Fin bit\n", rType, sessionNo)
		}
	default:
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: unknown/%d\n", rType, sessionNo, opcode)
	}

	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read Websocket finished\n", rType, sessionNo)
	return dataLen, nil
}
