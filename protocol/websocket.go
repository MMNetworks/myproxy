package protocol

import (
	"encoding/binary"
	"errors"
	"myproxy/logging"
	"net"
	"time"
)

const maxPayloadLength int = 16 * 65535

// track Session Sequence numbers and request state
// for Wireshark export
type WSStruct struct {
	// Websocket request
	Websocket bool

	// Websocket Connection
	WebsocketConn net.Conn
}

func WebsocketRead(request bool, conn net.Conn, timeOut int, sessionNo int64, buf []byte, mbuf []byte) (int, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var payload []byte
	var payloadLen int
	var dataLen int
	var offset int
	var opcode byte
	var fin bool
	var masked bool
	var maskKey [4]byte
	var rType string

	payload = make([]byte, maxPayloadLength)
	localBuf := make([]byte, 65*1024)
	payloadLen = 0
	dataLen = 0

	if request {
		rType = "request"
	} else {
		rType = "response"
	}
	logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Read Websocket %s\n", sessionNo, rType)

	for {
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeOut) * time.Second))
		start := time.Now()
		n, err := conn.Read(localBuf)
		elapsed := time.Since(start)
		logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Connection %s read took %d milliseconds\n", sessionNo, rType, elapsed.Milliseconds())
		if err != nil {
			return 0, err
		}

		logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Read %d bytes from %s\n", sessionNo, n, rType)
		if payloadLen == 0 {
			fin = localBuf[0]&0x80 != 0
			opcode = localBuf[0] & 0x0F
			masked = localBuf[1]&0x80 != 0
			payloadLen = int(localBuf[1] & 0x7F)
			offset = 2

			if payloadLen == 126 {
				if n < offset+2 {
					logging.Printf("ERROR", "WebsocketRead: SessionID:%d Too few data to determine Websocket payload length: %d<%d\n", sessionNo, n, offset+2)
					return 0, errors.New("Too few data to detemine Websocket payload length")
				}
				payloadLen = int(binary.BigEndian.Uint16(localBuf[offset : offset+2]))
				offset += 2
			} else if payloadLen == 127 {
				if n < offset+8 {
					logging.Printf("ERROR", "WebsocketRead: SessionID:%d Too few data to determine Websocket payload length: %d<%d\n", sessionNo, n, offset+8)
					return 0, errors.New("Too few data to detemine Websocket payload length")
				}
				payloadLen = int(binary.BigEndian.Uint64(localBuf[offset : offset+8]))
				offset += 8
			}

			if payloadLen > maxPayloadLength {
				logging.Printf("ERROR", "WebsocketRead: SessionID:%d Websocket payload too large to convert: %d>%d\n", sessionNo, payloadLen, maxPayloadLength)
				return 0, errors.New("Websocket data stream too long")
			}

			if masked {
				if n < offset+4 {
					logging.Printf("ERROR", "WebsocketRead: SessionID:%d Too few data to determine Websocket data mask: %d<%d\n", sessionNo, n, offset+4)
					return 0, errors.New("Too few Websocket data to get data mask")
				}
				copy(maskKey[:], localBuf[offset:offset+4])
				offset += 4
			}

			logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket Payload length: %d Masked bit: %t FIN bit: %t\n", sessionNo, payloadLen, masked, fin)

			switch opcode {
			case 0x0: // continuation
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: continuation\n", sessionNo)
			case 0x1: // Text frame
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: string\n", sessionNo)
			case 0x2: // Binary frame
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: binary\n", sessionNo)
			case 0x8: // Connection closed
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: close\n", sessionNo)
				copy(mbuf, localBuf[:n])
				copy(buf, localBuf[:n])
				return n, nil
			case 0x9: // Ping
				copy(mbuf, localBuf[:n])
				copy(buf, localBuf[:n])
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: ping\n", sessionNo)
				return n, nil
			case 0xA: // Pong
				copy(mbuf, localBuf[:n])
				copy(buf, localBuf[:n])
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: pong\n", sessionNo)
				return n, nil
			default:
				logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket type: unknown/%d\n", sessionNo, opcode)
				return n, nil
			}
			if n < offset+payloadLen {
				copy(mbuf, localBuf[:n])
				copy(payload, localBuf[offset:n])
				dataLen = n - offset
			} else {
				copy(mbuf, localBuf[:offset+payloadLen])
				copy(payload, localBuf[offset:offset+payloadLen])
				copy(buf, mbuf)
				if masked {
					for i := 0; i < payloadLen; i++ {
						buf[offset+i] ^= maskKey[i%4]
					}
				}

				if n > offset+payloadLen-dataLen {
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket data stream contains second payload: %d>%d bytes\n", sessionNo, n, offset+payloadLen-dataLen)
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket Offset: %d Payload length: %d DataLen: %d\n", sessionNo, offset, payloadLen, dataLen)
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket Masked bit: %t FIN bit: %t\n", sessionNo, masked, fin)

					// Need to work on processing fragments
					for i := offset + payloadLen + 1; i <= n; i++ {
						buf[i] = localBuf[i]
						mbuf[i] = localBuf[i]
					}
				}

				switch opcode {
				case 0x1: // Text frame
					//logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket string:\n%s\n\n", sessionNo, payload)
				case 0x2: // Binary frame
					//logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket string:\n%s\n\n", sessionNo, string(payload[:payloadLen]))
				}

				// bufLen := offset + payloadLen
				bufLen := n
				payloadLen = 0
				dataLen = 0
				return bufLen, nil
			}
		} else {
			if n < payloadLen-dataLen {
				copy(mbuf[offset+dataLen:], localBuf[:n])
				copy(payload[dataLen:], localBuf[:n])
				dataLen = dataLen + n
			} else {
				copy(mbuf[offset+dataLen:], localBuf[:payloadLen-dataLen])
				copy(payload[dataLen:], localBuf[:payloadLen-dataLen])
				copy(buf, mbuf)
				if masked {
					for i := 0; i < payloadLen; i++ {
						buf[offset+i] ^= maskKey[i%4]

					}
				}

				if n > offset+payloadLen-dataLen {
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket data stream contains second payload: %d>%d bytes\n", sessionNo, n, offset+payloadLen-dataLen)
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket Offset: %d Payload length: %d DataLen: %d\n", sessionNo, offset, payloadLen, dataLen)
					logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket Masked bit: %t FIN bit: %t\n", sessionNo, masked, fin)
					// Need to work on processing fragments
					for i := offset + payloadLen + 1; i <= n; i++ {
						buf[i] = localBuf[i]
						mbuf[i] = localBuf[i]
					}
				}

				switch opcode {
				case 0x1: // Text frame
					//logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket string:\n%s\n\n", sessionNo, payload[:payloadLen])
				case 0x2: // Binary frame
					//logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Websocket string:\n%s\n\n", sessionNo, string(payload[:payloadLen]))
				}

				//bufLen := offset + payloadLen
				bufLen := n
				payloadLen = 0
				dataLen = 0
				return bufLen, nil

			}
		}
	}
	logging.Printf("DEBUG", "WebsocketRead: SessionID:%d Read Websocket %s finished\n", sessionNo, rType)
	return 0, nil
}
