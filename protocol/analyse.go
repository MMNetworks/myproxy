// Package protocol handles Proxy/Websocket/Wireshark protocols
package protocol

import (
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"myproxy/logging"
	"regexp"
	"strconv"
	"strings"
)

// Pre-compiled regular expressions for protocol detection
var (
	sshPattern         = regexp.MustCompile(`^SSH-\d\.\d.*`)
	upgradePattern     = regexp.MustCompile(`\r\nUpgrade:.*\r\n`)
	httpPattern        = regexp.MustCompile(`^[a-zA-Z]+ [^ ]+ HTTP/\d\.\d\r\n`)
	ftpPattern         = regexp.MustCompile(`^(120|220|421).*\r\n`)
	upgradeRespPattern = regexp.MustCompile(`^HTTP/\d\.\d 101 .*\r\n`)
)

// AnalyseFirstPacket analyses the first request packet
func AnalyseFirstPacket(SessionNo int64, packet []byte) (string, string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)

	name, err := analyseAsTLSPacket(SessionNo, packet)
	if err == nil {
		return "TLS", "SNI name: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a TLS packet\n", SessionNo)

	name, err = analyseAsSSHPacket(SessionNo, packet)
	if err == nil {
		return "SSH", "Client: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a SSH packet\n", SessionNo)

	name, err = analyseAsUpgradePacket(SessionNo, packet)
	if err == nil {
		return "Upgrade", "Protocol: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not an Upgrade packet\n", SessionNo)

	name, err = analyseAsHTTPPacket(SessionNo, packet)
	if err == nil {
		return "HTTP", "Client: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a HTTP packet\n", SessionNo)

	return "Unknown", ""
}

// AnalyseFirstPacketResponse analyses the first response packet
func AnalyseFirstPacketResponse(SessionNo int64, packet []byte) (string, string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	//	name, err := analyseAsTLSPacketResponse(packet)
	//	if err == nil {
	//		return "TLS", "SNI name: "+name
	//	} else {
	//		logging.Printf("DEBUG", "analyseFirstPacket: Not a TLS packet\n")
	//	}
	name, err := analyseAsTLSPacketResponse(SessionNo, packet)
	if err == nil {
		return "TLS", "Version: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not a TLS packet\n", SessionNo)

	name, err = analyseAsSSHPacketResponse(SessionNo, packet)
	if err == nil {
		return "SSH", "Server: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not a SSH packet\n", SessionNo)

	name, err = analyseAsFTPPacketResponse(SessionNo, packet)
	if err == nil {
		return "FTP", "Server response: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not a FTP packet\n", SessionNo)

	name, err = analyseAsUpgradePacketResponse(SessionNo, packet)
	if err == nil {
		return "Upgrade", "Protocol: " + name
	}
	logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not an Upgrade packet\n", SessionNo)

	return "Unknown", ""
}

func analyseAsSSHPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if sshPattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	}
	logging.Printf("DEBUG", "analyseAsSSHPacket: SessionID:%d Not a SSH packet\n", SessionNo)

	return "", errors.New("not a ssh stream")
}

// Request-Header includes Upgrade: websocket
func analyseAsUpgradePacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if upgradePattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		upgradePos := strings.Index(msgString, "Upgrade: ")
		lenUpgrade := len("Upgrade: ")
		if upgradePos < 0 {
			upgradePos = 0
			lenUpgrade = 0
		}
		pos := strings.Index(msgString[upgradePos:], "\n")
		if strings.Index(msgString[upgradePos:], "\r") < pos {
			pos = strings.Index(msgString[upgradePos:], "\r")
		}
		return msgString[upgradePos+lenUpgrade : upgradePos+pos], nil
	}
	logging.Printf("DEBUG", "analyseAsUpgradePacket: SessionID:%d Not an Upgrade packet\n", SessionNo)

	return "", errors.New("not an upgrade")
}

// Request-Line   = Method SP Request-URI SP HTTP-Version
func analyseAsHTTPPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if httpPattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	}
	logging.Printf("DEBUG", "analyseAsHTTPPacket: SessionID:%d Not a HTTP packet\n", SessionNo)

	return "", errors.New("not a http stream")
}

func analyseAsTLSPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	//
	// Using https://www.agwa.name/blog/post/parsing_tls_client_hello_with_cryptobyte
	// and https://datatracker.ietf.org/doc/html/rfc6066#section-3 as guidance
	//
	// handshake record
	var recordType uint8
	var handshakeMessage cryptobyte.String
	var legacyRecordVersion uint16
	var recordLength uint16
	// Client Hello record
	var handshakeType uint8
	var clientHello cryptobyte.String
	var legacyVersion uint16
	var random []byte
	var legacySessionID []byte
	var ciphersuitesBytes cryptobyte.String
	var legacyCompressionMethods []uint8
	// Look for SNI in here
	var extensionsBytes cryptobyte.String
	var extType uint16
	var extData cryptobyte.String
	var sniBytes cryptobyte.String
	var sniNameType uint8
	var sniName cryptobyte.String
	var tlsVersionList cryptobyte.String

	packetMessage := cryptobyte.String(packet)

	if !packetMessage.ReadUint8(&recordType) || logging.TLSRecordType[recordType] != "handshake" {
		if logging.TLSRecordType[recordType] != "handshake" {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS handshake message. Record Type: %d/%s\n", SessionNo, recordType, logging.TLSRecordType[recordType])
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS handshake message. Could not read uint8\n", SessionNo)
		}
		goto END
	}

	if !packetMessage.ReadUint16(&legacyRecordVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read TLS handshake legacy record version\n", SessionNo)
		goto END
	} else {
		hex := fmt.Sprintf("%x", legacyRecordVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS legacy record version: %d/%s\n", SessionNo, legacyRecordVersion, logging.TLSString[hex])
	}

	if !packetMessage.ReadUint16(&recordLength) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read full TLS handshake message\n", SessionNo)
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS handshake record length: %d\n", SessionNo, recordLength)
		var message []byte
		if !packetMessage.ReadBytes(&message, int(recordLength)) {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full TLS handshake message\n", SessionNo)
			goto END
		}
		handshakeMessage = cryptobyte.String(message)
	}

	if !handshakeMessage.ReadUint8(&handshakeType) || logging.TLSHandshakeType[handshakeType] != "client_hello" {
		if logging.TLSHandshakeType[handshakeType] != "client_hello" {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS Client message. Message Type: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS Client message. Could not read uint8\n", SessionNo)
		}
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS Client message: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
	}

	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read full Client handshake message\n", SessionNo)
		goto END
	}

	if !handshakeMessage.Empty() {
		if !handshakeMessage.ReadUint8(&recordType) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS handsake record not read handshakeType\n", SessionNo)
			goto END
		} else {
			switch recordType {
			default:
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client handshake record with handshake type: %d/%s\n", SessionNo, recordType, logging.TLSRecordType[recordType])
			}
		}
	}

	if !clientHello.ReadUint16(&legacyVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello protocol version\n", SessionNo)
		goto END
	} else {
		hex := fmt.Sprintf("%x", legacyVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS protocol version: %d/%s\n", SessionNo, legacyVersion, logging.TLSString[hex])
	}

	if !clientHello.ReadBytes(&random, 32) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello random value\n", SessionNo)
		goto END
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID)) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello legacy session ID\n", SessionNo)
		goto END
	}

	if !clientHello.ReadUint16LengthPrefixed(&ciphersuitesBytes) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello cipher suite length\n", SessionNo)
		goto END
	}

	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		if !ciphersuitesBytes.ReadUint16(&ciphersuite) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello cipher suite\n", SessionNo)
			goto END

		}
		hex := fmt.Sprintf("%x", ciphersuite)
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello supported cipher suite: %d/%s\n", SessionNo, ciphersuite, logging.TLSCipher[hex])
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacyCompressionMethods)) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello compression methods\n", SessionNo)
		goto END
	}

	if !clientHello.ReadUint16LengthPrefixed(&extensionsBytes) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello extension bytes\n", SessionNo)
		goto END
	}

	if !clientHello.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello record not empty as it should be\n", SessionNo)
		goto END
	}

	for !extensionsBytes.Empty() {
		if !extensionsBytes.ReadUint16(&extType) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello extension type\n", SessionNo)
			goto END
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello extension type: %d/%s\n", SessionNo, extType, logging.TLSExtensionType[extType])
		}
		if !extensionsBytes.ReadUint16LengthPrefixed(&extData) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello extension data\n", SessionNo)
			goto END
		}
		// SNI extension
		if logging.TLSExtensionType[extType] == "server_name" {
			if extData.Empty() {
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Read Client Hello SNI name is empty\n", SessionNo)
			} else {
				if !extData.ReadUint16LengthPrefixed(&sniBytes) {
					logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello SNI data\n", SessionNo)
					goto END
				}
				for !sniBytes.Empty() {
					if !sniBytes.ReadUint8(&sniNameType) {
						logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello SNI name type\n", SessionNo)
						goto END
					} else {
						logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Read Client Hello SNI name type: %d\n", SessionNo, sniNameType)
					}
					if !sniBytes.ReadUint16LengthPrefixed(&sniName) {
						logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello SNI name\n", SessionNo)
						goto END
					} else {
						logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Read Client Hello SNI name: %s\n", SessionNo, string(sniName))
					}
				}

			}
		} else if logging.TLSExtensionType[extType] == "supported_versions" {
			// supported TLS Versions
			if !extData.ReadUint8LengthPrefixed(&tlsVersionList) {
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello TLS Version list\n", SessionNo)
				goto END
			}

			for !tlsVersionList.Empty() {
				var version uint16
				if !tlsVersionList.ReadUint16(&version) {
					logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello TLS Version data\n", SessionNo)
					goto END
				}
				hex := fmt.Sprintf("%x", version)
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello TLS Version supported: %d/%s\n", SessionNo, version, logging.TLSString[hex])
			}
		} else if logging.TLSExtensionType[extType] == "key_share" {
			var group uint16
			var keyExchange cryptobyte.String

			if !extData.ReadUint16(&group) || !extData.ReadUint16LengthPrefixed(&keyExchange) {
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello TLS Key share data\n", SessionNo)
			} else {
				keyExchangeBytes := []byte(keyExchange)
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello TLS Key group: 0x%04x Exchange: %x\n", SessionNo, group, keyExchangeBytes)
			}
		}
	}

	return string(sniName), nil

END:
	return "", errors.New("not a tls stream")

}

func analyseAsTLSPacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	//
	// Using https://www.agwa.name/blog/post/parsing_tls_client_hello_with_cryptobyte
	// and https://datatracker.ietf.org/doc/html/rfc6066#section-3 as guidance
	//
	// handshake record
	var recordType uint8
	var legacyRecordVersion uint16
	var handshakeMessage cryptobyte.String
	var recordLength uint16
	// Server Hello record
	var handshakeType uint8
	var serverHello cryptobyte.String
	var legacyVersion uint16
	var random []byte
	var legacySessionID []byte
	var ciphersuite uint16
	var version uint16
	var legacyCompressionMethod uint8
	// Other records
	var handshakeBody cryptobyte.String
	// Look for SNI in here
	var extensionsBytes cryptobyte.String
	var extType uint16
	var extData cryptobyte.String
	var sniBytes cryptobyte.String
	var sniNameType uint8
	var sniName cryptobyte.String
	var tlsVersion = "Unknown"
	var tlsCipher = "Unknown"
	var rString string

	packetMessage := cryptobyte.String(packet)

	if !packetMessage.ReadUint8(&recordType) || logging.TLSRecordType[recordType] != "handshake" {
		if logging.TLSRecordType[recordType] != "handshake" {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Not a TLS handshake record. Record Type: %d/%s\n", SessionNo, recordType, logging.TLSRecordType[recordType])
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Not a TLS handshake record. Could not read uint8\n", SessionNo)
		}
		goto END
	}

	if !packetMessage.ReadUint16(&legacyRecordVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read TLS handshake legacy record version\n", SessionNo)
		goto END
	} else {
		hex := fmt.Sprintf("%x", legacyRecordVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake legacy record version: %d/%s\n", SessionNo, legacyRecordVersion, logging.TLSString[hex])
	}

	if !packetMessage.ReadUint16(&recordLength) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read TLS handshake record length: %d\n", SessionNo, recordLength)
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake record length: %d\n", SessionNo, recordLength)
		var message []byte
		if !packetMessage.ReadBytes(&message, int(recordLength)) {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full TLS handshake message\n", SessionNo)
			goto END
		}
		handshakeMessage = cryptobyte.String(message)
	}

	if !handshakeMessage.ReadUint8(&handshakeType) || logging.TLSHandshakeType[handshakeType] != "server_hello" {
		if logging.TLSHandshakeType[handshakeType] != "server_hello" {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Not a TLS Server Hello message. Message Type: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Not a TLS Server Hello message. Could not read uint8\n", SessionNo)
		}
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS Server Hello message: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
	}

	//	if !handshakeMessage.ReadUint24LengthPrefixed(&serverHello) || !handshakeMessage.Empty() {
	if !handshakeMessage.ReadUint24LengthPrefixed(&serverHello) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full Server handshake message\n", SessionNo)
		goto END
	}

	if !serverHello.ReadUint16(&legacyVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello protocol version\n", SessionNo)
		goto END
	} else {
		tlsVersion = fmt.Sprintf("%x", legacyVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS protocol version: %d/%s\n", SessionNo, legacyVersion, logging.TLSString[tlsVersion])
	}

	if !serverHello.ReadBytes(&random, 32) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello random value\n", SessionNo)
		goto END
	}

	if !serverHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID)) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello legacy session ID\n", SessionNo)
		goto END
	}

	if !serverHello.ReadUint16(&ciphersuite) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello cipher suite\n", SessionNo)
		goto END
	}
	tlsCipher = fmt.Sprintf("%x", ciphersuite)
	logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Server Hello negotiated cipher suite: %d/%s\n", SessionNo, ciphersuite, logging.TLSCipher[tlsCipher])

	if !serverHello.ReadUint8(&legacyCompressionMethod) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello compression methods\n", SessionNo)
		goto END
	}

	if !serverHello.ReadUint16LengthPrefixed(&extensionsBytes) {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello extension bytes\n", SessionNo)
		goto END
	}

	if !serverHello.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Server Hello record not empty as it should be\n", SessionNo)
		goto END
	}

	for !extensionsBytes.Empty() {
		if !extensionsBytes.ReadUint16(&extType) {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello extension type\n", SessionNo)
			goto END
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Server Hello extension type: %d/%s\n", SessionNo, extType, logging.TLSExtensionType[extType])
		}
		if !extensionsBytes.ReadUint16LengthPrefixed(&extData) {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello extension data\n", SessionNo)
			goto END
		}
		// SNI extension
		if logging.TLSExtensionType[extType] == "server_name" {
			if extData.Empty() {
				logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Read Server Hello SNI name is empty\n", SessionNo)
			} else {
				if !extData.ReadUint16LengthPrefixed(&sniBytes) {
					logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello SNI data\n", SessionNo)
					goto END
				} else {
					for !sniBytes.Empty() {
						if !sniBytes.ReadUint8(&sniNameType) {
							logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello SNI name type\n", SessionNo)
							goto END
						} else {
							logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Read Server Hello SNI name type: %d\n", SessionNo, sniNameType)
						}
						if !sniBytes.ReadUint16LengthPrefixed(&sniName) {
							logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello SNI name\n", SessionNo)
							goto END
						} else {
							logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Read Server Hello SNI name: %s\n", SessionNo, string(sniName))
						}
					}
				}
			}
		} else if logging.TLSExtensionType[extType] == "supported_versions" {
			// negotiated TLS Versions
			if !extData.ReadUint16(&version) {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read Server Hello TLS Version list\n", SessionNo)
				goto END
			}

			tlsVersion = fmt.Sprintf("%x", version)
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Server Hello TLS Version negotiated: %d/%s\n", SessionNo, version, logging.TLSString[tlsVersion])

		}
	}
	if !handshakeMessage.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake message not empty\n", SessionNo)
		goto END
	}

	for !packetMessage.Empty() {
		if !packetMessage.ReadUint8(&recordType) {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake could not read message type\n", SessionNo)
			goto END
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake message: %d/%s\n", SessionNo, recordType, logging.TLSRecordType[recordType])
			if logging.TLSRecordType[recordType] == "application_data" {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake is TLS 1.3 application data\n", SessionNo)
				break
			}
			if !packetMessage.ReadUint16(&legacyRecordVersion) {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read handshake legacy record version\n", SessionNo)
				break
			} else {
				hex := fmt.Sprintf("%x", legacyRecordVersion)
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS legacy record version: %d/%s\n", SessionNo, legacyRecordVersion, logging.TLSString[hex])
			}

			if !packetMessage.ReadUint16(&recordLength) {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full handshake message\n", SessionNo)
				break
			} else {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake record length: %d\n", SessionNo, recordLength)
				var message []byte
				cbLen := len(packetMessage)
				if !packetMessage.ReadBytes(&message, int(recordLength)) {
					logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full TLS handshake message. Record length %d > packet length %d\n", SessionNo, recordLength, cbLen)
					break
				}
				handshakeMessage = cryptobyte.String(message)
			}

			if logging.TLSRecordType[recordType] == "change_cipher_spec" {
				logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake is TLS 1.3 change_cipher_spec with no data\n", SessionNo)
				handshakeMessage.ReadUint8(&handshakeType)
			} else {
				if !handshakeMessage.ReadUint8(&handshakeType) {
					logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full handshake message\n", SessionNo)
					break
				} else {
					logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake message type: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
				}
				var messageLength uint32
				if !handshakeMessage.ReadUint24(&messageLength) {
					logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full TLS handshake message length\n", SessionNo)
				} else {
					if messageLength > uint32(recordLength) {
						logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake message length %d > record length %d. Can't deal with fragmentation yet\n", SessionNo, messageLength, recordLength)
						break
					}
					var message []byte
					if !handshakeMessage.ReadBytes(&message, int(messageLength)) {
						logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Could not read full TLS handshake message\n", SessionNo)
						break
					}
					handshakeBody = cryptobyte.String(message)
				VEND:
					//771/303/TLS 1.2
					//772/304/TLS 1.3
					switch tlsVersion {
					case "303": // TLS 1.2
						switch handshakeType {
						case 11: // certificate
							var certList cryptobyte.String
							if !handshakeBody.ReadUint24LengthPrefixed(&certList) {
								logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake failed to read certificate list\n", SessionNo)
								goto VEND
							}

							for !certList.Empty() {
								var certBytes cryptobyte.String
								if !certList.ReadUint24LengthPrefixed(&certBytes) {
									logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake failed to read certificate list\n", SessionNo)
									goto VEND
								}
								parsedCert, err := x509.ParseCertificate(certBytes)
								if err != nil {
									logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake failed to parse certificate\n", SessionNo)
									goto VEND
								}
								logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Certificate Issuer: %s\n", SessionNo, parsedCert.Issuer.String())
							}
						default:
							logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d Server message type: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType])
							// goto END
						}
					case "304": // TLS 1.3
					default:
						logging.Printf("DEBUG", "analyseAsTLSPacketResponse: SessionID:%d TLS handshake record %d/%s for version: %d/%s\n", SessionNo, handshakeType, logging.TLSHandshakeType[handshakeType], version, logging.TLSString[tlsVersion])
						// goto END
					}
				}
			}
		}
	}

	rString = logging.TLSString[tlsVersion]
	if logging.TLSString[tlsVersion] == "" {
		rString = strconv.Itoa(int(version))
	}
	if logging.TLSCipher[tlsCipher] == "" {
		rString = rString + ":" + strconv.Itoa(int(ciphersuite))
	} else {
		rString = rString + ":" + logging.TLSCipher[tlsCipher]
	}

	return rString, nil

END:
	return "", errors.New("not a tls stream")

}

func analyseAsFTPPacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if ftpPattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	}
	logging.Printf("DEBUG", "analyseAsFTPPacketResponse: SessionID:%d Not a FTP packet\n", SessionNo)

	return "", errors.New("not a ftp stream")
}

// Response-Line   = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
func analyseAsUpgradePacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if upgradeRespPattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		upgradePos := strings.Index(msgString, "Upgrade: ")
		lenUpgrade := len("Upgrade: ")
		if upgradePos < 0 {
			upgradePos = 0
			lenUpgrade = 0
		}
		pos := strings.Index(msgString[upgradePos:], "\n")
		if strings.Index(msgString[upgradePos:], "\r") < pos {
			pos = strings.Index(msgString[upgradePos:], "\r")
		}
		return msgString[upgradePos+lenUpgrade : upgradePos+pos], nil
	}
	logging.Printf("DEBUG", "analyseAsUpgradePacketResponse: SessionID:%d Not an Upgrade packet\n", SessionNo)

	return "", errors.New("not an upgrade")
}

func analyseAsSSHPacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	if sshPattern.Match([]byte(initialMessage)) {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	}
	logging.Printf("DEBUG", "analyseAsSSHPacketResponse: SessionID:%d Not a SSH packet\n", SessionNo)

	return "", errors.New("not a ssh stream")
}
