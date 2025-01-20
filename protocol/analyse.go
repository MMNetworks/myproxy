package protocol

import (
	"golang.org/x/crypto/cryptobyte"
	"myproxy/logging"
	"errors"
	"regexp"
	"strings"
	"fmt"
)

func AnalyseFirstPacket(packet []byte) (string, string) {

	name, err := analyseAsTLSPacket(packet)
	if err == nil {
		return "TLS", "SNI name: "+name
	} else {	   
		logging.Printf("DEBUG", "analyseFirstPacket: Not a TLS packet\n")
	}
	name, err = analyseAsSSHPacket(packet)
	if err == nil {
		return "SSH", "Client: "+name
	} else {	   
		logging.Printf("DEBUG", "analyseFirstPacket: Not a SSH packet\n")
	}	   
	name, err = analyseAsHTTPPacket(packet)
	if err == nil {
		return "HTTP", "Client: "+name
	} else {	   
		logging.Printf("DEBUG", "analyseFirstPacket: Not a HTTP packet\n")
	}	   
	return "Unknown",""
}

func AnalyseFirstPacketResponse(packet []byte) (string, string) {

//	name, err := analyseAsTLSPacketResponse(packet)
//	if err == nil {
//		return "TLS", "SNI name: "+name
//	} else {	   
//		logging.Printf("DEBUG", "analyseFirstPacket: Not a TLS packet\n")
//	}
	name, err := analyseAsSSHPacketResponse(packet)
	if err == nil {
		return "SSH", "Server: "+name
	} else {	   
		logging.Printf("DEBUG", "analyseFirstPacketResponse: Not a SSH packet\n")
	}	   
	name, err = analyseAsFTPPacketResponse(packet)
	if err == nil {
		return "FTP", "Server response: "+name
	} else {
		logging.Printf("DEBUG", "analyseFirstPacketResponse: Not a FTP packet\n")
	}
	return "Unknown",""
}

func analyseAsSSHPacket(packet []byte) (string, error){
	initialMessage := cryptobyte.String(packet)
	isSSH, _ := regexp.MatchString("SSH-\\d\\.\\d.*", string(initialMessage))
	if isSSH {
		msgString := string(initialMessage) 
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos { 
			pos = strings.Index(msgString, "\r")
		}
		return  msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsSSHPacket: Not a SSH packet\n")
	}
	return  "", errors.New("Not a SSH stream")
}

// Request-Line   = Method SP Request-URI SP HTTP-Version
func analyseAsHTTPPacket(packet []byte) (string, error){
	initialMessage := cryptobyte.String(packet)
	isHTTP , _ := regexp.MatchString("[a-zA-Z]+ [^ ]+ HTTP/\\d\\.\\d\\r\\n", string(initialMessage))
	if isHTTP {
		msgString := string(initialMessage) 
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos { 
			pos = strings.Index(msgString, "\r")
		}
		return  msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsHTTPPacket: packet a HTTP packet\n")
	}
	return  "", errors.New("Not a SSH stream")
}

func analyseAsTLSPacket(packet []byte) (string, error){
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


	if !handshakeMessage.ReadUint8(&contentType) || contentType != 22  {
		if contentType != 22 {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Not a TLS handshake message. Message Type: %d\n",contentType)
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Not a TLS handshake message. Can't read uint8\n")
		}
		goto END
        } 	

	if !handshakeMessage.ReadUint16(&legacyRecordVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read handshake legacy record version\n")
		goto END
	} else {
		hex := fmt.Sprintf("%x",legacyRecordVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: TLS legacy record version: %s\n", hex)
	}

	if !handshakeMessage.ReadUint16(&messageLength) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read full handshake message\n")
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: TLS handshake message length: %d\n",messageLength)
	}

	if !handshakeMessage.ReadUint8(&messageType) || messageType != 1 {
		if messageType != 1 {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Not a TLS Client Hello message. Message Type: %d\n",messageType)
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Not a TLS Client Hello message. Can't read uint8\n")
		}
		goto END
	} else {
		logging.Printf("DEBUG", "analyseAsTLSPacket: TLS Client Hello message: %d\n",messageType)
	}

	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) || !handshakeMessage.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read full Client Hello handshake message\n")
		goto END
	}

	if !clientHello.ReadUint16(&legacyVersion) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello protocol version\n")
		goto END
	} else {
		hex := fmt.Sprintf("%x",legacyVersion)
		logging.Printf("DEBUG", "analyseAsTLSPacket: TLS protocol version: %s\n",hex)
	}

	if !clientHello.ReadBytes(&random, 32) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello random value\n")
		goto END
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID)) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello legacy session ID\n")
		goto END
	}

	if !clientHello.ReadUint16LengthPrefixed(&ciphersuitesBytes) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello cypher suite length\n")
		goto END
	}

	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		if !ciphersuitesBytes.ReadUint16(&ciphersuite) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello cypher suite\n")
			goto END
		
		}
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacyCompressionMethods)) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello compression methods\n")
		goto END
	}

	if !clientHello.ReadUint16LengthPrefixed(&extensionsBytes) {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello extension bytes\n")
		goto END
	}

	if !clientHello.Empty() {
		logging.Printf("DEBUG", "analyseAsTLSPacket: Client Hello record not empty as it should be\n")
		goto END
	}

	for !extensionsBytes.Empty() {
		if !extensionsBytes.ReadUint16(&extType) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello extension type\n")
			goto END
		} else {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Client Hello extension type %d\n",extType)
		}
		if !extensionsBytes.ReadUint16LengthPrefixed(&extData) {
			logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello extension data\n")
			goto END
		}
		// SNI extension
		if extType == 0 {
			if !extData.ReadUint16LengthPrefixed(&sniBytes) {
				logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello SNI data\n")
				goto END
			}
			for !sniBytes.Empty() {
				if  !sniBytes.ReadUint8(&sniNameType) {
					logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello SNI name type\n")
					goto END
				} else {
					logging.Printf("DEBUG", "analyseAsTLSPacket: Read Client Hello SNI name type: %d\n",sniNameType)
				}
				if  !sniBytes.ReadUint16LengthPrefixed(&sniName) {
					logging.Printf("DEBUG", "analyseAsTLSPacket: Could not read Client Hello SNI name\n")
					goto END
				} else {
					logging.Printf("DEBUG", "analyseAsTLSPacket: Read Client Hello SNI name %s\n",string(sniName))
				}
			}
		}
	}

	return  string(sniName), nil


	END:
	return  "", errors.New("Not a TLS stream")

}

func analyseAsFTPPacketResponse(packet []byte) (string, error){
	initialMessage := cryptobyte.String(packet)
	isFTP, _ := regexp.MatchString("(120|220|421).*\\r\\n", string(initialMessage))
	if isFTP {
		msgString := string(initialMessage) 
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos { 
			pos = strings.Index(msgString, "\r")
		}
		return  msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsFTPPacketResponse: Not a FTP packet\n")
	}
	return  "", errors.New("Not a FTP stream")
}

func analyseAsSSHPacketResponse(packet []byte) (string, error){
	initialMessage := cryptobyte.String(packet)
	isSSH, _ := regexp.MatchString("SSH-\\d\\.\\d.*", string(initialMessage))
	if isSSH {
		msgString := string(initialMessage) 
		pos := strings.Index(msgString, "\n")
		if strings.Index(msgString, "\r") < pos { 
			pos = strings.Index(msgString, "\r")
		}
		return  msgString[:pos], nil
	} else {
		logging.Printf("DEBUG", "analyseAsSSHPacketResponse: Not a SSH packet\n")
	}
	return  "", errors.New("Not a SSH stream")
}


