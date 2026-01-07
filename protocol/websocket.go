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

	// Request buffer
	ReqBuf [maxReadLength]byte

	// Response buffer
	ResBuf [maxReadLength]byte

	// Request Length
	ReqLen int

	// Response length
	ResLen int
}

// attach WS Struct to request context
// avoid import loop by using interface
type WSState interface {
	GetWSState() *WSStruct
}

var errTooShort = errors.New("Websocket data stream too short")
var errTooLong = errors.New("Websocket data stream too long")

func getPayloadLength(sessionNo int64, buf []byte) (int, int, byte, bool, bool, [4]byte, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var payloadLen int
	var dataLen int = len(buf)
	var offset int
	var opcode byte
	var fin bool
	var masked bool
	var maskKey [4]byte
	var maxPayloadLength int = readconfig.Config.WebSocket.MaxPayloadLength

	fin = buf[0]&0x80 != 0
	opcode = buf[0] & 0x0F
	masked = buf[1]&0x80 != 0
	payloadLen = int(buf[1] & 0x7F)
	offset = 2

	if payloadLen == 126 {
		if dataLen < offset+2 {
			logging.Printf("ERROR", "getPayloadLength: SessionID:%d Too few data to determine Websocket payload length: %d<%d\n", sessionNo, dataLen, offset+2)
			return 0, 0, 0, true, false, [4]byte{}, errTooShort
		}
		payloadLen = int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	} else if payloadLen == 127 {
		if dataLen < offset+8 {
			logging.Printf("ERROR", "getPayloadLength: SessionID:%d Too few data to determine Websocket payload length: %d<%d\n", sessionNo, dataLen, offset+8)
			return 0, 0, 0, true, false, [4]byte{}, errTooShort
		}
		payloadLen = int(binary.BigEndian.Uint64(buf[offset : offset+8]))
		offset += 8
	}

	if payloadLen > maxPayloadLength {
		logging.Printf("ERROR", "getPayloadLength: SessionID:%d Websocket payload too large to convert: %d>%d\n", sessionNo, payloadLen, maxPayloadLength)
		return 0, 0, 0, true, false, [4]byte{}, errTooLong
	}

	if masked {
		if dataLen < offset+4 {
			logging.Printf("ERROR", "getPayloadLength: SessionID:%d Too few data to determine Websocket data mask: %d<%d\n", sessionNo, dataLen, offset+4)
			return 0, 0, 0, true, false, [4]byte{}, errTooShort
		}
		copy(maskKey[:], buf[offset:offset+4])
		offset += 4
	}
	return payloadLen, offset, opcode, fin, masked, maskKey, nil
}

func WebsocketRead(wss WSState, request bool, conn net.Conn, timeOut int, sessionNo int64, buf []byte, mbuf []byte) (int, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var dataLen = 0
	var payload []byte
	var rType string
	var maxPayloadLength int = readconfig.Config.WebSocket.MaxPayloadLength

	// Need to store full payload in a buffer for unmasking which is needed for AV scanning of stream
	// buf is unmasked buffer, mbuf masked buffer returned
	// Requires 2 additional internal buffers in case two websocket session are in one tcp packet
	// First localbuf buffer is for read data
	// Second buffer contains overspill kept over multiple WebosocketRead calls
	wsState := wss.GetWSState()
	payload = make([]byte, maxPayloadLength)
	localBuf := make([]byte, maxReadLength)
	// Full websocket Payload length of frame
	// websocket Payload length in this tcp packet

	if request {
		rType = "Request"
	} else {
		rType = "Response"
	}

	// Fill buffer with previous websocket frame data
	if request && wsState.ReqLen > 0 {
		for i := 0; i < wsState.ReqLen; i++ {
			buf[i] = wsState.ReqBuf[i]
			mbuf[i] = wsState.ReqBuf[i]
		}
		dataLen = wsState.ReqLen
		wsState.ReqLen = 0
	} else if !request && wsState.ResLen > 0 {
		for i := 0; i < wsState.ResLen; i++ {
			buf[i] = wsState.ResBuf[i]
			mbuf[i] = wsState.ResBuf[i]
		}
		dataLen = wsState.ResLen
		wsState.ResLen = 0
	}

	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d previous websocket data fragment length: %d\n", rType, sessionNo, dataLen)
	for dataLen <= 14 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		start := time.Now()
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d start read\n", rType, sessionNo)
		n, err := conn.Read(localBuf)
		elapsed := time.Since(start)
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d read of %d bytes took %d milliseconds\n", rType, sessionNo, n, elapsed.Milliseconds())
		if err != nil {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d read error: %v\n", rType, sessionNo, err)
			return 0, err
		}
		dStart := 0
		if dataLen > 0 {
			dStart = 1
		}
		for i := 0; i < n; i++ {
			buf[dStart+dataLen+i] = localBuf[i]
			mbuf[dStart+dataLen+i] = localBuf[i]
		}
		dataLen = dataLen + n

		// Check websocket header is read
		_, _, _, _, _, _, err = getPayloadLength(sessionNo, mbuf)

		if err == nil || err == errTooLong {
			break
		}
	}
	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d websocket data length %d\n", rType, sessionNo, dataLen)

	payloadLen, offset, opcode, fin, masked, maskKey, err := getPayloadLength(sessionNo, mbuf)

	if err != nil {
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d payload length read error: %v\n", rType, sessionNo, err)
		return 0, err
	}
	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Connection: %s\n", rType, sessionNo, c2s(conn))
	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d State: %t Timeout: %d\n", rType, sessionNo, wsState.Websocket, timeOut)
	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d PayloadLength:%d Offset: %d DataLength: %d FIN bit: %t Masked bit: %t\n", rType, sessionNo, payloadLen, offset, dataLen, fin, masked)

	for dataLen < offset+payloadLen {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		start := time.Now()
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d start read\n", rType, sessionNo)
		n, err := conn.Read(localBuf)
		elapsed := time.Since(start)
		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d read of %d bytes took %d milliseconds\n", rType, sessionNo, n, elapsed.Milliseconds())
		if err != nil {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d read error: %v\n", rType, sessionNo, err)
			return 0, err
		}
		for i := 0; i < n; i++ {
			buf[dataLen+1+i] = localBuf[i]
			mbuf[dataLen+1+i] = localBuf[i]
		}
		dataLen = dataLen + n

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
			return dataLen, nil
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
			return dataLen, nil
		}

		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d bytes Expected %d bytes\n", rType, sessionNo, dataLen, offset+payloadLen)
		if dataLen < offset+payloadLen {
			// Copy payload and continue reading frame
			copy(payload, mbuf[offset:dataLen])
		} else {
			// Copy payload, return masked and unmasked data and buffer fragment of next frame
			copy(payload, mbuf[offset:offset+payloadLen])
			copy(buf, mbuf[offset:offset+payloadLen])
			if masked {
				for i := 0; i < payloadLen; i++ {
					buf[offset+i] ^= maskKey[i%4]
				}
			}

			if dataLen > offset+payloadLen {
				logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket data stream contains second payload: %d>%d bytes\n", rType, sessionNo, dataLen, offset+payloadLen)

			}

			switch opcode {
			case 0x1: // Text frame
				//logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket string:\n%s\n\n", rType, sessionNo, payload)
			case 0x2: // Binary frame
				//logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket string:\n%s\n\n", rType, sessionNo, string(payload[:payloadLen]))
			}

			bufLen := offset + payloadLen
			fragLen := dataLen - bufLen
			if fragLen > 0 {
				// Save additionally read data
				logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Buffer fragment: %d\n", rType, sessionNo, fragLen)
				if request {
					for i := 0; i < fragLen; i++ {
						wsState.ReqBuf[i] = mbuf[bufLen+i+1]
					}
					wsState.ReqLen = fragLen
				} else {
					for i := 0; i < fragLen; i++ {
						wsState.ResBuf[i] = mbuf[bufLen+i+1]
					}
					wsState.ResLen = fragLen
				}
			}
			payloadLen = 0
			dataLen = 0
			return bufLen, nil
		}

	}

	// Read more then one websocket frame
	// Return complete frame and store fragment
	if dataLen >= offset+payloadLen {

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
			return dataLen, nil
		case 0x9: // Ping
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: ping\n", rType, sessionNo)
			if !fin {
				logging.Printf("ERROR", "WebsocketRead%s: SessionID:%d Ping with no FIN bit\n", rType, sessionNo)
			}
		case 0xA: // Pong
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: pong\n", rType, sessionNo)
			if !fin {
				logging.Printf("ERROR", "WebsocketRead%s: SessionID:%d Pong with no FIN bit\n", rType, sessionNo)
			}
		default:
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket type: unknown/%d\n", rType, sessionNo, opcode)
			return dataLen, nil
		}

		logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read %d bytes Expected %d bytes\n", rType, sessionNo, dataLen, offset+payloadLen)

		copy(payload, mbuf[offset:offset+payloadLen])
		copy(buf, mbuf[offset:offset+payloadLen])
		if masked {
			for i := 0; i < payloadLen; i++ {
				buf[offset+i] ^= maskKey[i%4]
			}
		}

		if dataLen > offset+payloadLen {
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket data stream contains second payload: %d>%d bytes\n", rType, sessionNo, dataLen, offset+payloadLen)

		}

		switch opcode {
		case 0x1: // Text frame
			//logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket string:\n%s\n\n", rType, sessionNo, payload)
		case 0x2: // Binary frame
			//logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Websocket string:\n%s\n\n", rType, sessionNo, (payload[:payloadLen]))
		}

		bufLen := offset + payloadLen
		fragLen := dataLen - bufLen
		if fragLen > 0 {
			// Save additionally read data
			logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Buffer fragment: %d\n", rType, sessionNo, fragLen)
			if request {
				for i := 0; i < fragLen; i++ {
					wsState.ReqBuf[i] = mbuf[bufLen+i+1]
				}
				wsState.ReqLen = fragLen
			} else {
				for i := 0; i < fragLen; i++ {
					wsState.ResBuf[i] = mbuf[bufLen+i+1]
				}
				wsState.ResLen = fragLen
			}
		}
		payloadLen = 0
		dataLen = 0
		return bufLen, nil

	}
	logging.Printf("DEBUG", "WebsocketRead%s: SessionID:%d Read Websocket finished\n", rType, sessionNo)
	return 0, nil
}
