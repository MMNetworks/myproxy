package protocol

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"myproxy/logging"
	"regexp"
	"strings"
)

func AnalyseFirstPacket(SessionNo int64, packet []byte) (string, string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)

	name, err := analyseAsTLSPacket(SessionNo, packet)
	if err == nil {
		return "TLS", "SNI name: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a TLS packet\n", SessionNo)
	}
	name, err = analyseAsSSHPacket(SessionNo, packet)
	if err == nil {
		return "SSH", "Client: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a SSH packet\n", SessionNo)
	}
	name, err = analyseAsHTTPPacket(SessionNo, packet)
	if err == nil {
		return "HTTP", "Client: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacket: SessionID:%d Not a HTTP packet\n", SessionNo)
	}
	return "Unknown", ""
}

func AnalyseFirstPacketResponse(SessionNo int64, packet []byte) (string, string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	//	name, err := analyseAsTLSPacketResponse(packet)
	//	if err == nil {
	//		return "TLS", "SNI name: "+name
	//	} else {
	//		logging.Printf("DEBUG", "analyseFirstPacket: Not a TLS packet\n")
	//	}
	name, err := analyseAsSSHPacketResponse(SessionNo, packet)
	if err == nil {
		return "SSH", "Server: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not a SSH packet\n", SessionNo)
	}
	name, err = analyseAsFTPPacketResponse(SessionNo, packet)
	if err == nil {
		return "FTP", "Server response: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not a FTP packet\n", SessionNo)
	}
	name, err = analyseAsUpgradePacketResponse(SessionNo, packet)
	if err == nil {
		return "Upgrade", "Protocol: " + name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacketResponse: SessionID:%d Not an Upgrade packet\n", SessionNo)
	}
	return "Unknown", ""
}

func analyseAsSSHPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	isSSH, _ := regexp.MatchString("^SSH-\\d\\.\\d.*", string(initialMessage))
	if isSSH {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsSSHPacket: SessionID:%d Not a SSH packet\n", SessionNo)
	}
	return "", errors.New("Not a SSH stream")
}

// Request-Line   = Method SP Request-URI SP HTTP-Version
func analyseAsHTTPPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	isHTTP, _ := regexp.MatchString("^[a-zA-Z]+ [^ ]+ HTTP/\\d\\.\\d\\r\\n", string(initialMessage))
	if isHTTP {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsHTTPPacket: SessionID:%d Not a HTTP packet\n", SessionNo)
	}
	return "", errors.New("Not a HTTP stream")
}

func analyseAsTLSPacket(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	//
	// Using https://www.agwa.name/blog/post/parsing_tls_client_hello_with_cryptobyte
	// and https://datatracker.ietf.org/doc/html/rfc6066#section-3 as guidance
	//
	// handshake record
	var contentType uint8 = 0
	var legacyRecordVersion uint16 = 0
	var messageLength uint16 = 0
	// Client Hello record
	var messageType uint8 = 0
	var clientHello cryptobyte.String
	var legacyVersion uint16 = 0
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

	handshakeMessage := cryptobyte.String(packet)

	if !handshakeMessage.ReadUint8(&contentType) || contentType != 22 {
		if contentType != 22 {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS handshake message. Message Type: %d\n", SessionNo, contentType)
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS handshake message. Can't read uint8\n", SessionNo)
		}
		goto END
	}

	if !handshakeMessage.ReadUint16(&legacyRecordVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read handshake legacy record version\n", SessionNo)
		goto END
	} else {
		hex := fmt.Sprintf("%x", legacyRecordVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS legacy record version: %s\n", SessionNo, hex)
	}

	if !handshakeMessage.ReadUint16(&messageLength) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read full handshake message\n", SessionNo)
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS handshake message length: %d\n", SessionNo, messageLength)
	}

	if !handshakeMessage.ReadUint8(&messageType) || messageType != 1 {
		if messageType != 1 {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS Client Hello message. Message Type: %d\n", SessionNo, messageType)
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Not a TLS Client Hello message. Can't read uint8\n", SessionNo)
		}
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS Client Hello message: %d\n", SessionNo, messageType)
	}

	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) || !handshakeMessage.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read full Client Hello handshake message\n", SessionNo)
		goto END
	}

	if !clientHello.ReadUint16(&legacyVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello protocol version\n", SessionNo)
		goto END
	} else {
		hex := fmt.Sprintf("%x", legacyVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d TLS protocol version: %s\n", SessionNo, hex)
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
		logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello cypher suite length\n", SessionNo)
		goto END
	}

	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		if !ciphersuitesBytes.ReadUint16(&ciphersuite) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello cypher suite\n", SessionNo)
			goto END

		}
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
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Client Hello extension type %d\n", SessionNo, extType)
		}
		if !extensionsBytes.ReadUint16LengthPrefixed(&extData) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Could not read Client Hello extension data\n", SessionNo)
			goto END
		}
		// SNI extension
		if extType == 0 {
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
					logging.Printf("DEBUG", "analyseAsTLSPacket: SessionID:%d Read Client Hello SNI name %s\n", SessionNo, string(sniName))
				}
			}
		}
	}

	return string(sniName), nil

END:
	return "", errors.New("Not a TLS stream")

}

func analyseAsFTPPacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	isFTP, _ := regexp.MatchString("^(120|220|421).*\\r\\n", string(initialMessage))
	if isFTP {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsFTPPacketResponse: SessionID:%d Not a FTP packet\n", SessionNo)
	}
	return "", errors.New("Not a FTP stream")
}

func analyseAsUpgradePacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	isUpgrade, _ := regexp.MatchString("^HTTP/\\d\\.\\d 101.*\\r\\n", string(initialMessage))
	if isUpgrade {
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
	} else {
		logging.Printf("DEBUG", "analyseAsUpgradePacketResponse: SessionID:%d Not an Upgrade packet\n", SessionNo)
	}
	return "", errors.New("Not an Upgrade")
}

func analyseAsSSHPacketResponse(SessionNo int64, packet []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), SessionNo)
	initialMessage := cryptobyte.String(packet)
	isSSH, _ := regexp.MatchString("^SSH-\\d\\.\\d.*", string(initialMessage))
	if isSSH {
		msgString := string(initialMessage)
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos {
			pos = strings.Index(msgString, "\r")
		}
		return msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsSSHPacketResponse: SessionID:%d Not a SSH packet\n", SessionNo)
	}
	return "", errors.New("Not a SSH stream")
}
