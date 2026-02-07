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
	"sync"
	"time"
)

// Leverages Wireshark TCP connection reader
// wireshark -k -i TCP@127.0.0.1:19000

// Use Mutex for connection status check
type MyMutex struct {
	mu sync.Mutex
}

func (m *MyMutex) Lock() {
	//logging.Printf("DEBUG", "MyMutex: SessionID:%d Locking...\n", -1 )
	m.mu.Lock()
	//logging.Printf("DEBUG", "MyMutex: SessionID:%d Locked\n", -1 )
}

func (m *MyMutex) Unlock() {
	//logging.Printf("DEBUG", "MyMutex: SessionID:%d Unlocking...\n", -1 )
	m.mu.Unlock()
	//logging.Printf("DEBUG", "MyMutex: SessionID:%d Unlocked\n", -1 )
}

type safeStatus struct {
	mu     MyMutex
	active bool
}

// Wireshark connection state
var status safeStatus

// Wireshark Writer
var pcapWriter *pcapgo.Writer

var tcpMutex sync.Mutex

// track Session Sequence numbers and request state
// for Wireshark export
type TCPStruct struct {
	tcpSequence    uint32
	tcpAcknowledge uint32
	tcpClientRand  uint32
	tcpServerRand  uint32
	tcpLength      uint32
	wasRequest     bool
}

type wiresharkStruct struct {
	logTime     time.Time
	state       TCPState
	sessionNo   int64
	request     bool
	source      string
	destination string
	data        []byte
}

var wiresharkChan = make(chan wiresharkStruct, 65000) // Buffered channel

func processor() {
	for data := range wiresharkChan {
		_writeWireshark(data.logTime, data.state, data.request, data.sessionNo, data.source, data.destination, data.data)
	}
}

// attach tcp Struct to request context
// avoid import loop by using interface
type TCPState interface {
	GetTCPState() *TCPStruct
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
	rand.Seed(time.Now().UnixNano())
	status.mu.Lock()
	status.active = false
	status.mu.Unlock()
	go processor()
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
		status.mu.Lock()
		if status.active {
			status.mu.Unlock()
			_ = <-notify
			logging.Printf("INFO", "AcceptWireshark: SessionID:%d Connection from %s lost\n", 0, remoteAddr)
			status.mu.Lock()
			status.active = false
		}
		status.mu.Unlock()
		logging.Printf("INFO", "AcceptWireshark: SessionID:%d Waiting for connection\n", 0)
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
			logging.Printf("ERROR", "AcceptWireshark: SessionID:%d Empty remote address\n", 0)
			conn.Close()
			continue

		}
		readconfig.Config.Wireshark.Mu.Lock()
		defer readconfig.Config.Wireshark.Mu.Unlock()
		for _, rule := range readconfig.Config.Wireshark.Rules {
			cidrStr := rule.IP
			// IncExc string format (!)subnet
			logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Check against IncExc Subnet %s\n", 0, cidrStr)
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
				ipAddr := net.ParseIP(cidrStr)
				if ipAddr == nil {
					logging.Printf("ERROR", "AcceptWireshark: SessionID:%d source address %s is not an IP\n", 0, cidrStr)
					continue
				}
				if ipAddr.To4() != nil {
					cidrStr = cidrStr + "/32"
				} else {
					cidrStr = cidrStr + "/128"
				}
			}
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				logging.Printf("ERROR", "AcceptWireshark: SessionID:%d Could not parse cidr: %s\n", 0, cidrStr)
				continue
			}
			rAddr, _, err := net.SplitHostPort(remoteAddr)
			if err != nil {
				//	                        if errors.Is(err, net.ErrMissingPort) {
				if strings.Contains(err.Error(), "missing port in address") {
					rAddr = remoteAddr
				} else {
					logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not convert forwarded ip %s: %v\n", 0, remoteAddr, err)
				}
			}
			remoteAddr = rAddr
			remoteIP := net.ParseIP(remoteAddr)
			matchRemote = cidr.Contains(remoteIP)
			if matchRemote {
				logging.Printf("DEBUG", "AcceptWireshark: SessionID:%d Remote address %s matched %s\n", 0, remoteAddr, cidrStr)
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
		// This only works as the functionis don't process any input from wireshark
		// i.e. data is only send (unfortunately unencrypted so best only via localhost)
		// Any data read from wireshark would be ignored
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

		// If this is reached a new wireshark connection has been established
		// Send Wireshark Header
		status.mu.Lock()
		status.active = true
		status.mu.Unlock()
		pcapWriter = pcapgo.NewWriter(conn)
		if err := pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
			logging.Printf("ERROR", "AcceptWireshark: SessionID:%d Could not write pcap header\n", 0)
			continue
		}

	}
}

func WriteWireshark(tcp TCPState, isRequest bool, sessionNo int64, src string, dst string, data []byte) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)

	if !readconfig.Config.Wireshark.Enable {
		return nil
	}

	timeStamp := time.Now()
	wiresharkData := wiresharkStruct{logTime: timeStamp, state: tcp, sessionNo: sessionNo, request: isRequest, source: src, destination: dst, data: data}

	wiresharkChan <- wiresharkData

	return nil
}

func _writeWireshark(timeStamp time.Time, tcp TCPState, isRequest bool, sessionNo int64, src string, dst string, data []byte) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var err error
	var tcpSeq uint32
	var tcpAck uint32

	tcpMutex.Lock()
	tcpState := tcp.GetTCPState()
	defer tcpMutex.Unlock()

	status.mu.Lock()
	if !status.active {
		status.mu.Unlock()
		return nil
	}
	status.mu.Unlock()

	srcIP, srcPortString, err := net.SplitHostPort(src)
	if err != nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not convert source address for %s: %v\n", sessionNo, src, err)
		return err
	}
	dstIP, dstPortString, err := net.SplitHostPort(dst)
	if err != nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not convert destination address for %s: %v\n", sessionNo, dst, err)
		return err
	}
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not convert source port for %s to int: %v\n", sessionNo, src, err)
		return err
	}
	dstPort, err := strconv.Atoi(dstPortString)
	if err != nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not convert destination port for %s to int: %v\n", sessionNo, dst, err)
		return err
	}

	if tcpState.tcpSequence == 0 {
		tcpState.tcpClientRand = rand.Uint32() & 0xFFFFFF // Avoid overflow by never starting to high
		tcpState.tcpServerRand = rand.Uint32() & 0xFFFFFF
		tcpState.wasRequest = true
		tcpState.tcpLength = 0
		tcpState.tcpSequence = 1
		tcpState.tcpAcknowledge = 1
		err := writeSynAck(timeStamp, tcpState, sessionNo, srcIP, dstIP, srcPort, dstPort)
		if err != nil {
			logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not write SYN/SYN-ACK/ACK: %v\n", sessionNo, err)
		}
	}
	logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Add client/server random number %d/%d \n", sessionNo, tcpState.tcpClientRand, tcpState.tcpServerRand)

	// Use fake MAC
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Source MAC
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Add Identifier %d to packet\n", sessionNo, uint16(sessionNo&0xFFFF))

	// Create IP layer
	ipAddr := net.ParseIP(srcIP)
	if ipAddr == nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d source address %s is not an IP\n", sessionNo, srcIP)
		return errors.New("Not an IP")
	}

	start := 0
	end := len(data)
	step := 1460 // MTU 1500

	// Loop from start to end, stepping by 1460
	logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Total data length received: %d\n", sessionNo, len(data))
	for i := start; i < end; i += step {

		logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Request state wasRequest/isRequest: %t/%t\n", sessionNo, tcpState.wasRequest, isRequest)
		if isRequest {
			if tcpState.wasRequest { // Was previous packet a client request ?
				tcpState.tcpSequence = tcpState.tcpSequence + tcpState.tcpLength
			} else {
				tcpSeq = tcpState.tcpAcknowledge
				tcpState.tcpAcknowledge = tcpState.tcpSequence + tcpState.tcpLength
				tcpState.tcpSequence = tcpSeq
			}
			tcpSeq = tcpState.tcpClientRand + tcpState.tcpSequence
			tcpAck = tcpState.tcpServerRand + tcpState.tcpAcknowledge
			tcpState.tcpLength = uint32(len(data[i:min(len(data), i+step)]))
			tcpState.wasRequest = true // This is a client request
		} else {
			if tcpState.wasRequest { // Was previous packet a client request ?
				tcpSeq = tcpState.tcpAcknowledge
				tcpState.tcpAcknowledge = tcpState.tcpSequence + tcpState.tcpLength
				tcpState.tcpSequence = tcpSeq
			} else {
				tcpState.tcpSequence = tcpState.tcpSequence + tcpState.tcpLength
			}
			tcpSeq = tcpState.tcpServerRand + tcpState.tcpSequence
			tcpAck = tcpState.tcpClientRand + tcpState.tcpAcknowledge
			tcpState.tcpLength = uint32(len(data[i:min(len(data), i+step)]))
			tcpState.wasRequest = false // This is a server response
		}
		logging.Printf("DEBUG", "WriteWireshark: SessionID:%d Added Sequence/Acknowledge %d/%d to packet. New length %d (wasRequest/isRequest: %t/%t)\n", sessionNo, tcpState.tcpSequence, tcpState.tcpAcknowledge, tcpState.tcpLength, tcpState.wasRequest, isRequest)

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

		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		if ipAddr.To4() != nil {
			ip := layers.IPv4{
				SrcIP:    net.ParseIP(srcIP), // Source IP
				DstIP:    net.ParseIP(dstIP), // Destination IP
				Protocol: layers.IPProtocolTCP,
				Version:  4,
				Id:       uint16(sessionNo & 0xFFFF),
				IHL:      5,
				TTL:      64,
			}

			// Set the TCP header length based on the options
			tcp.SetNetworkLayerForChecksum(&ip)

			err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
			if err != nil {
				logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not serialize packet: %v\n", sessionNo, err)
				return err
			}

		} else {
			ip := layers.IPv6{
				SrcIP:        net.ParseIP(srcIP),   // Source IPv6
				DstIP:        net.ParseIP(dstIP),   // Destination IPv6
				NextHeader:   layers.IPProtocolTCP, // Upper-layer protocol
				Version:      6,
				HopLimit:     64, // like TTL in IPv4
				TrafficClass: 0,  // optional QoS
				FlowLabel:    0,  // optional flow label
			}
			// Set the TCP header length based on the options
			tcp.SetNetworkLayerForChecksum(&ip)

			err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
			if err != nil {
				logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not serialize packet: %v\n", sessionNo, err)
				return err
			}
		}
		// Write the packet to the PCAP connection
		if pcapWriter != nil {
			err = pcapWriter.WritePacket(gopacket.CaptureInfo{
				Timestamp:     timeStamp,
				CaptureLength: len(buf.Bytes()),
				Length:        len(buf.Bytes()),
			}, buf.Bytes())
		} else {
			err = errors.New("Empty pcapWriter pointer")
		}
		if err != nil {
			logging.Printf("ERROR", "WriteWireshark: SessionID:%d Could not write packet: %v\n", sessionNo, err)
			return err
		}
	}
	return nil

}

func writeSynAck(timeStamp time.Time, tcpState *TCPStruct, sessionNo int64, srcIP string, dstIP string, srcPort int, dstPort int) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)
	var err error

	// Use fake MAC
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Source MAC
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Destination MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	tcpSeq := tcpState.tcpClientRand
	tcpAck := tcpState.tcpServerRand

	logging.Printf("DEBUG", "WriteSynAck: SessionID:%d Created SYN/SYN-ACK/ACK for IP packet Identifier %d\n", sessionNo, uint16(sessionNo&0xFFFF))

	logging.Printf("DEBUG", "WriteSynAck: SessionID:%d SourceIP: %s DestinationIP: %s\n", sessionNo, srcIP, dstIP)
	// Create IP layer
	ipAddr := net.ParseIP(srcIP)
	if ipAddr == nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d source address %s is not an IP\n", sessionNo, srcIP)
		return errors.New("Not an IP")
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

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if ipAddr.To4() != nil {
		ip := layers.IPv4{
			SrcIP:    net.ParseIP(srcIP), // Source IP
			DstIP:    net.ParseIP(dstIP), // Destination IP
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			Id:       uint16(sessionNo & 0xFFFF),
			IHL:      5,
			TTL:      64,
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize SYN packet: %v\n", sessionNo, err)
			return err
		}
	} else {
		ip := layers.IPv6{
			SrcIP:        net.ParseIP(srcIP),   // Source IPv6
			DstIP:        net.ParseIP(dstIP),   // Destination IPv6
			NextHeader:   layers.IPProtocolTCP, // Upper-layer protocol
			Version:      6,
			HopLimit:     64, // like TTL in IPv4
			TrafficClass: 0,  // optional QoS
			FlowLabel:    0,  // optional flow label
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize SYN packet: %v\n", sessionNo, err)
			return err
		}
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     timeStamp,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not write SYN packet: %v\n", sessionNo, err)
		return err
	}

	// Create IP layer
	ipAddr = net.ParseIP(srcIP)
	if ipAddr == nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d source address %s is not an IP\n", sessionNo, srcIP)
		return errors.New("Not an IP")
	}

	tcpSeq = tcpState.tcpServerRand
	tcpAck = tcpState.tcpClientRand + 1

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

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if ipAddr.To4() != nil {
		ip := layers.IPv4{
			SrcIP:    net.ParseIP(dstIP), // Source IP
			DstIP:    net.ParseIP(srcIP), // Destination IP
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			Id:       uint16(sessionNo & 0xFFFF),
			IHL:      5,
			TTL:      64,
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize SYN-ACK packet: %v\n", sessionNo, err)
			return err
		}
	} else {
		ip := layers.IPv6{
			SrcIP:        net.ParseIP(srcIP),   // Source IPv6
			DstIP:        net.ParseIP(dstIP),   // Destination IPv6
			NextHeader:   layers.IPProtocolTCP, // Upper-layer protocol
			Version:      6,
			HopLimit:     64, // like TTL in IPv4
			TrafficClass: 0,  // optional QoS
			FlowLabel:    0,  // optional flow label
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize SYN-ACK packet: %v\n", sessionNo, err)
			return err
		}
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     timeStamp,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not write SYN-ACK packet: %v\n", sessionNo, err)
		return err
	}

	// Create IP layer
	ipAddr = net.ParseIP(srcIP)
	if ipAddr == nil {
		logging.Printf("ERROR", "WriteWireshark: SessionID:%d source address %s is not an IP\n", sessionNo, srcIP)
		return errors.New("Not an IP")
	}

	tcpSeq = tcpState.tcpClientRand + 1
	tcpAck = tcpState.tcpServerRand + 1

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

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if ipAddr.To4() != nil {
		ip := layers.IPv4{
			SrcIP:    net.ParseIP(srcIP), // Source IP
			DstIP:    net.ParseIP(dstIP), // Destination IP
			Protocol: layers.IPProtocolTCP,
			Version:  4,
			Id:       uint16(sessionNo & 0xFFFF),
			IHL:      5,
			TTL:      64,
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize ACK packet: %v\n", sessionNo, err)
			return err
		}
	} else {
		ip := layers.IPv6{
			SrcIP:        net.ParseIP(srcIP),   // Source IPv6
			DstIP:        net.ParseIP(dstIP),   // Destination IPv6
			NextHeader:   layers.IPProtocolTCP, // Upper-layer protocol
			Version:      6,
			HopLimit:     64, // like TTL in IPv4
			TrafficClass: 0,  // optional QoS
			FlowLabel:    0,  // optional flow label
		}
		// Set the TCP header length based on the options
		tcp.SetNetworkLayerForChecksum(&ip)

		err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, payload)
		if err != nil {
			logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not serialize ACK packet: %v\n", sessionNo, err)
			return err
		}
	}

	// Write the packet to the PCAP connection
	if pcapWriter != nil {
		err = pcapWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:     timeStamp,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}, buf.Bytes())
	} else {
		err = errors.New("Empty pcapWriter pointer")
	}
	if err != nil {
		logging.Printf("ERROR", "WriteSynAck: SessionID:%d Could not write ACK packet: %v\n", sessionNo, err)
		return err
	}

	return nil
}
