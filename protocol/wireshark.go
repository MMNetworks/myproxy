package protocol

import (
	"errors"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"math/rand"
	"myproxy/logging"
	"myproxy/readconfig"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Leverages Wireshark TCP connection reader
// wireshark -k -i TCP@127.0.0.1:19000
var concurrent int = 0
var pcapWriter *pcapgo.Writer

// track Session Sequence numbers and request state
// for Wireshark export
var tcpSequence map[int64]uint32
var tcpAcknowledge map[int64]uint32
var tcpClientRand map[int64]uint32
var tcpServerRand map[int64]uint32
var tcpLength map[int64]uint32
var wasRequest map[int64]bool

func CleanupWireshark(sessionNo int64) {
	// Cleanup Wiresharl map entries
	delete(tcpSequence, sessionNo)
	delete(tcpAcknowledge, sessionNo)
	delete(tcpClientRand, sessionNo)
	delete(tcpServerRand, sessionNo)
	delete(tcpLength, sessionNo)
	delete(wasRequest, sessionNo)
}

// Listen on given IP & Port
func ListenWireshark(listen string) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), 0)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		logging.Printf("ERROR", "ListenWireshark: SessionID:%d Starting server on %s failed\n", 0, listen)
		return err

	}
	// defer listener.Close()

	// Accept connection in background
	tcpSequence = make(map[int64]uint32)
	tcpAcknowledge = make(map[int64]uint32)
	tcpClientRand = make(map[int64]uint32)
	tcpServerRand = make(map[int64]uint32)
	tcpLength = make(map[int64]uint32)
	wasRequest = make(map[int64]bool)
	rand.Seed(time.Now().UnixNano())
	go acceptWireshark(listener)

	return nil
}

// Wait for Clients and very if allowed and create initial pacp Header for new connection
// Need to deal with disconnecting and reconnecting Wireshark client
func acceptWireshark(listener net.Listener) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), 0)

	// Notify when wireshark connection breaks
	notify := make(chan error)
	remoteAddr := ""

	//
	// Loop to accept restarted wireshark
	//
	for {
		// Make sure only one wireshark connection is established
		// Reset if lost
		if concurrent > 0 {
			_ = <-notify
			logging.Printf("INFO", "AcceptWireshark: SessionID:%d Connection from %s lost\n", 0, remoteAddr)
			concurrent = 0
		}
		logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Waiting for connection\n", 0)
		conn, err := listener.Accept()
		if err != nil {
			logging.Printf("ERROR", "AcceptWireshark: SessionID:%d Error accepting connection %v\n", 0, err)
			continue
		}

		//
		// Check IP filtering
		//
		remoteAddr = conn.RemoteAddr().String()
		matchRemote := false
		if remoteAddr == "" {
			logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Empty remote address\n", 0)
			conn.Close()
			continue

		}
		for _, cidrStr := range readconfig.Config.Wireshark.IncExc {
			// IncExc string format (!)subnet
			logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d IncExc Subnet %s\n", 0, cidrStr)
			isEmpty, _ := regexp.MatchString("^[ ]*$", cidrStr)
			if isEmpty {
				continue
			}
			isNeg := strings.Index(cidrStr, "!") == 0
			hasSlash := strings.Index(cidrStr, "/") > -1
			if isNeg {
				cidrStr = cidrStr[1:]
			}
			if !hasSlash {
				cidrStr = cidrStr + "/32"
			}
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Cannot parse cidr: %s\n", 0, cidrStr)
				continue
			}
			cpos := strings.Index(remoteAddr, ":")
			if cpos != -1 {
				remoteAddr = remoteAddr[:cpos]
			}
			remoteIP := net.ParseIP(remoteAddr)
			matchRemote = cidr.Contains(remoteIP)
			if matchRemote {
				logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Remote address %s matches %s\n", 0, remoteAddr, cidrStr)
				break
			} else {
				logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Remote address %s did not match %s\n", 0, remoteAddr, cidrStr)
			}

		}
		if !matchRemote {
			logging.Printf("INFO", "AcceptWireshark: SessionID:%d Did not accept connection from %s\n", 0, remoteAddr)
			conn.Close()
			continue
		}

		logging.Printf("INFO", "AcceptWireshark: SessionID:%d Accepted connection from %s\n", 0, remoteAddr)

		// Check in background if  wireshark connection is alive
		go func(c net.Conn) {
			buf := make([]byte, 1)
			for {
				c.SetReadDeadline(time.Now().Add(1 * time.Second))
				_, err := c.Read(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// No data, but still connected
					} else {
						// Disconnected or other error
						notify <- err // connection closed or error
						return
					}
				}
			}
		}(conn)

		// If his is reached a new wireshark connection has been established
		// Send Wireshark Header
		concurrent = 1
		pcapWriter = pcapgo.NewWriter(conn)
		if err := pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Could not write pcap header\n", 0)
			continue
		}

	}
}

func WriteWireshark(isRequest bool, sessionNo int64, src string, dst string, data []byte) error {
	var err error
	var tcpSeq uint32
	var tcpAck uint32

	if concurrent == 0 {
		logging.Printf("DEBUG", "WriteWireshark: SessionID:%d No wireshark connection available\n", sessionNo)
		return nil
	}

	srcIP := src
	dstIP := dst
	srcPort := -1
	dstPort := -1
	cpos := strings.Index(src, ":")
	if cpos != -1 {
		srcIP = src[:cpos]
		srcPort, err = strconv.Atoi(src[cpos+1:])
		if err != nil {
			logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Cannot convert source port for %s to int %v\n", sessionNo, src, err)
			return err
		}

	}
	cpos = strings.Index(dst, ":")
	if cpos != -1 {
		dstIP = dst[:cpos]
		dstPort, err = strconv.Atoi(dst[cpos+1:])
		if err != nil {
			logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Cannot convert destination port for %s to int %v\n", sessionNo, dst, err)
			return err
		}
	}

	if tcpSequence[sessionNo] == 0 {
		tcpClientRand[sessionNo] = rand.Uint32() & 0xFFFFFF // Avoid overflow by never starting to high
		tcpServerRand[sessionNo] = rand.Uint32() & 0xFFFFFF
		wasRequest[sessionNo] = true
		tcpLength[sessionNo] = 0
		tcpSequence[sessionNo] = 1
		tcpAcknowledge[sessionNo] = 1
		err := writeSynAck(sessionNo, srcIP, dstIP, srcPort, dstPort)
		if err != nil {
			logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Cannot write SYN/SYN-ACK/ACK %v\n", sessionNo, err)
		}
	}
	logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Add client/server random number %d/%d \n", sessionNo, tcpClientRand[sessionNo], tcpServerRand[sessionNo])

	// Use fake MAC
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Source MAC
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Add Identifier %d to packet\n", sessionNo, uint16(sessionNo&0xFFFF))
	// Create IP layer
	ip := layers.IPv4{
		SrcIP:    net.ParseIP(srcIP), // Source IP
		DstIP:    net.ParseIP(dstIP), // Destination IP
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		Id:       uint16(sessionNo & 0xFFFF),
		IHL:      5,
		TTL:      64,
	}

	start := 0
	end := len(data)
	step := 1460 // MTU 1500

	// Loop from start to end, stepping by 1460
	for i := start; i < end; i += step {

		logging.Printf("DEBUG", "WriteWireshark: SessionID:%d wasRequest/isRequest: %t/%t\n", sessionNo, wasRequest[sessionNo], isRequest)
		if isRequest {
			if wasRequest[sessionNo] { // Was previous packet a client request ?
				tcpSequence[sessionNo] = tcpSequence[sessionNo] + tcpLength[sessionNo]
			} else {
				tcpSeq = tcpAcknowledge[sessionNo]
				tcpAcknowledge[sessionNo] = tcpSequence[sessionNo] + tcpLength[sessionNo]
				tcpSequence[sessionNo] = tcpSeq
			}
			tcpSeq = tcpClientRand[sessionNo] + tcpSequence[sessionNo]
			tcpAck = tcpServerRand[sessionNo] + tcpAcknowledge[sessionNo]
			tcpLength[sessionNo] = uint32(len(data[i:min(len(data), i+step)]))
			wasRequest[sessionNo] = true // This is a client request
		} else {
			if wasRequest[sessionNo] { // Was previous packet a client request ?
				tcpSeq = tcpAcknowledge[sessionNo]
				tcpAcknowledge[sessionNo] = tcpSequence[sessionNo] + tcpLength[sessionNo]
				tcpSequence[sessionNo] = tcpSeq
			} else {
				tcpSequence[sessionNo] = tcpSequence[sessionNo] + tcpLength[sessionNo]
			}
			tcpSeq = tcpServerRand[sessionNo] + tcpSequence[sessionNo]
			tcpAck = tcpClientRand[sessionNo] + tcpAcknowledge[sessionNo]
			tcpLength[sessionNo] = uint32(len(data[i:min(len(data), i+step)]))
			wasRequest[sessionNo] = false // This is a server response
		}
		logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Add Sequence/Acknowledge %d/%d to packet. New length %d (wasRequest/isRequest: %t/%t)\n", sessionNo, tcpSequence[sessionNo], tcpAcknowledge[sessionNo], tcpLength[sessionNo], wasRequest[sessionNo], isRequest)

		// Create TCP layer
		tcp := layers.TCP{
			SrcPort: layers.TCPPort(srcPort), // Source port
			DstPort: layers.TCPPort(dstPort), // Destination port
			Window:  65535,                   // Non-zero window size
			ACK:     true,                    // Set ACK flag
			Seq:     tcpSeq,
			Ack:     tcpAck,
			//SYN:     true,                  // Set SYN flag
			// Set the TCP options if needed
			// MSS only with SYN packet
			//Options: []layers.TCPOption{
			//      {
			//              OptionType: layers.TCPOptionKindMSS, // Maximum Segment Size option (2)
			//              OptionData: []byte{0x05, 0xb4}, // MSS value (1460 bytes)
			//      },
			//},
		}

		payload := gopacket.Payload(data[i:min(len(data), i+step)])

		// Serialize the layers
		buf := gopacket.NewSerializeBuffer()

		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Could not serialize packet %v\n", sessionNo, err)
			return err
		}

		// Write the packet to the PCAP connection
		if pcapWriter != nil {
			err = pcapWriter.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(buf.Bytes()),
				Length:        len(buf.Bytes()),
			}, buf.Bytes())
		} else {
			err = errors.New("Empty pcapWriter pointer")
		}
		if err != nil {
			logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Could not write packet %v\n", sessionNo, err)
			return err
		}
	}
	return nil

}

func writeSynAck(sessionNo int64, srcIP string, dstIP string, srcPort int, dstPort int) error {
	// Use fake MAC
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Source MAC
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	tcpSeq := tcpClientRand[sessionNo]
	tcpAck := tcpServerRand[sessionNo]

	logging.Printf("DEBUG", "WriteSynAck: SessionID:%d Create SYN/SYN-ACK/ACK for Identifier %d to packet\n", sessionNo, uint16(sessionNo&0xFFFF))
	// Create IP layer
	ip := layers.IPv4{
		SrcIP:    net.ParseIP(srcIP), // Source IP
		DstIP:    net.ParseIP(dstIP), // Destination IP
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		Id:       uint16(sessionNo & 0xFFFF),
		IHL:      5,
		TTL:      64,
	}

	// Create TCP layer
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort), // Source port
		DstPort: layers.TCPPort(dstPort), // Destination port
		Window:  65535,                   // Non-zero window size
		ACK:     false,                   // UnSet ACK flag
		Seq:     tcpSeq,
		Ack:     0,
		SYN:     true, // Set SYN flag
		// Set the TCP options if needed
		// MSS only with SYN packet
		Options: []layers.TCPOption{
			{
				OptionType: layers.TCPOptionKindMSS, // Maximum Segment Size option (2)
				OptionData: []byte{0x05, 0xb4},      // MSS value (1460 bytes)
			},
		},
	}

	emptyBytes := make([]byte, 0)
	payload := gopacket.Payload(emptyBytes)

	// Serialize the layers
	buf := gopacket.NewSerializeBuffer()

	// Set the TCP header length based on the options
	tcp.SetNetworkLayerForChecksum(&ip)

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
	if err != nil {
		logging.Printf("DEBUG", "WritwSynAck: SessionID:%d Could not serialize SYN packet %v\n", sessionNo, err)
		return err
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("DEBUG", "WriteSynAck: SessionID:%d Could not write SYN packet %v\n", sessionNo, err)
		return err
	}

	// Create IP layer
	ip = layers.IPv4{
		SrcIP:    net.ParseIP(dstIP), // Source IP
		DstIP:    net.ParseIP(srcIP), // Destination IP
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		Id:       uint16(sessionNo & 0xFFFF),
		IHL:      5,
		TTL:      64,
	}

	tcpSeq = tcpServerRand[sessionNo]
	tcpAck = tcpClientRand[sessionNo] + 1

	// Create TCP layer
	tcp = layers.TCP{
		SrcPort: layers.TCPPort(dstPort), // Source port
		DstPort: layers.TCPPort(srcPort), // Destination port
		Window:  65535,                   // Non-zero window size
		ACK:     true,                    // Set ACK flag
		Seq:     tcpSeq,
		Ack:     tcpAck,
		SYN:     true, // Set SYN flag
		// Set the TCP options if needed
		// MSS only with SYN packet
		// Options: []layers.TCPOption{
		//      {
		//              OptionType: layers.TCPOptionKindMSS, // Maximum Segment Size option (2)
		//              OptionData: []byte{0x05, 0xb4}, // MSS value (1460 bytes)
		//      },
		//},
	}

	payload = gopacket.Payload(emptyBytes)

	// Serialize the layers
	buf = gopacket.NewSerializeBuffer()

	// Set the TCP header length based on the options
	tcp.SetNetworkLayerForChecksum(&ip)

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
	if err != nil {
		logging.Printf("DEBUG", "WritwSynAck: SessionID:%d Could not serialize SYN-ACK packet %v\n", sessionNo, err)
		return err
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("DEBUG", "WriteSynAck: SessionID:%d Could not write SYN-ACK packet %v\n", sessionNo, err)
		return err
	}

	// Create IP layer
	ip = layers.IPv4{
		SrcIP:    net.ParseIP(srcIP), // Source IP
		DstIP:    net.ParseIP(dstIP), // Destination IP
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		Id:       uint16(sessionNo & 0xFFFF),
		IHL:      5,
		TTL:      64,
	}

	tcpSeq = tcpClientRand[sessionNo] + 1
	tcpAck = tcpServerRand[sessionNo] + 1

	// Create TCP layer
	tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort), // Source port
		DstPort: layers.TCPPort(dstPort), // Destination port
		Window:  65535,                   // Non-zero window size
		ACK:     true,                    // UnSet ACK flag
		Seq:     tcpSeq,
		Ack:     tcpAck,
		SYN:     false, // Set SYN flag
		// Set the TCP options if needed
		// MSS only with SYN packet
		// Options: []layers.TCPOption{
		//      {
		//              OptionType: layers.TCPOptionKindMSS, // Maximum Segment Size option (2)
		//              OptionData: []byte{0x05, 0xb4}, // MSS value (1460 bytes)
		//      },
		//},
	}

	payload = gopacket.Payload(emptyBytes)

	// Serialize the layers
	buf = gopacket.NewSerializeBuffer()

	// Set the TCP header length based on the options
	tcp.SetNetworkLayerForChecksum(&ip)

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
	if err != nil {
		logging.Printf("DEBUG", "WritwSynAck: SessionID:%d Could not serialize ACK packet %v\n", sessionNo, err)
		return err
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("DEBUG", "WriteSynAck: SessionID:%d Could not write ACK packet %v\n", sessionNo, err)
		return err
	}

	return nil
}
