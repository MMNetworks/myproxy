// HTTPS Server to front clamd daemon fo secure remote access
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/dutchcoders/go-clamd"

	// "net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"
)

var allowedCommands = map[string]bool{
	"PING":      true,
	"VERSION":   true,
	"INSTREAM":  true,
	"NINSTREAM": true, // terminate command with \n
	"ZINSTREAM": true, // terminate command with \0
	//"STATS":     true,
}

type configuration struct {
	debug              bool
	clamdSocketPath    string
	wrapperTLS         bool
	wrapperCert        string
	wrapperKey         string
	wrapperMTLS        bool
	wrapperClientCerts string
	wrapperIP          string
	wrapperPort        string
	wrapperCidr        string
	wrapperFilter      string
}

// Define a struct to hold the JSON data
type clamdData struct {
	Command string `json:"command"`
	Size    int64  `json:"size"`
	Data    string `json:"data"`
}
type clamdResponseData struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

func cleanUntrustedString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 { // printable ASCII
			b.WriteRune(r)
		}
	}
	return b.String()
}

func main() {
	args := os.Args[:]

	// Initial config
	config := configuration{
		debug:              false,
		clamdSocketPath:    "/var/run/clamav/clamd.sock",
		wrapperTLS:         true,
		wrapperCert:        "cert.pem",
		wrapperKey:         "key.pem",
		wrapperMTLS:        true,
		wrapperClientCerts: "client-ca.pem",
		wrapperIP:          "127.0.0.1",
		wrapperPort:        "3320",
		wrapperCidr:        "127.0.0.1",
		wrapperFilter:      "-",
	}
	CommandLine := flag.NewFlagSet("command_filtering_stream", flag.ExitOnError)

	CommandLine.BoolVar(&config.debug, "debug", config.debug, "Create debug output")
	CommandLine.BoolVar(&config.wrapperTLS, "tls", config.wrapperTLS, "Require TLS")
	CommandLine.StringVar(&config.wrapperCert, "cert", config.wrapperCert, "Specify certificate pem file")
	CommandLine.StringVar(&config.wrapperKey, "key", config.wrapperKey, "Specify key pem file")
	CommandLine.BoolVar(&config.wrapperMTLS, "mtls", config.wrapperMTLS, "Require mutual TLS")
	CommandLine.StringVar(&config.wrapperClientCerts, "clientcert", config.wrapperClientCerts, "Specify client certificates pem file")
	CommandLine.StringVar(&config.wrapperIP, "ip", config.wrapperIP, "Specify listening interface ip")
	CommandLine.StringVar(&config.wrapperPort, "port", config.wrapperPort, "Specify listening port")
	CommandLine.StringVar(&config.wrapperFilter, "acl", config.wrapperFilter, "Specify acl regex for remote IPs")
	CommandLine.StringVar(&config.wrapperCidr, "cidr", config.wrapperCidr, "Specify list of CIDR seperated by | for remote IPs")
	CommandLine.StringVar(&config.clamdSocketPath, "socket", config.clamdSocketPath, "Path to clamd socket")

	err := CommandLine.Parse(args[1:])
	if err != nil {
		log.Printf("ERROR: Rrror parsing arguments: %v\n", err)
	}

	if config.wrapperTLS {
		// Load server certificate and private key
		serverCert, err := tls.LoadX509KeyPair(config.wrapperCert, config.wrapperKey)
		if err != nil {
			log.Printf("Could not load certificate/key: %v\n", err)
			return
		}

		var tlsConfig *tls.Config
		if config.wrapperMTLS {
			// Create a new TLS configuration
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,           // Require client certificate
				ClientCAs:    loadClientCAs(config.wrapperClientCerts), // Load CA for client cert validation
			}
		} else {
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{serverCert},
			}
		}
		// Create a new HTTP server
		server := &http.Server{
			Addr:              config.wrapperIP + ":" + config.wrapperPort,
			Handler:           serviceHandler(config),
			ReadHeaderTimeout: 2 * time.Second,
			TLSConfig:         tlsConfig,
		}

		log.Println("Starting server on https://" + config.wrapperIP + ":" + config.wrapperPort)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Printf("Could not start server: %v\n", err)
			return
		}
	} else {
		// Create a new HTTP server
		server := &http.Server{
			Addr:              config.wrapperIP + ":" + config.wrapperPort,
			Handler:           serviceHandler(config),
			ReadHeaderTimeout: 2 * time.Second,
		}
		log.Println("Starting server on https://localhost:8-")
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Could not start server: %v\n", err)
			return
		}
	}
}

// loadClientCAs loads the CA certificate for client certificate validation
func loadClientCAs(clientCerts string) *x509.CertPool {
	// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
	caCert, err := os.ReadFile(clientCerts)
	if err != nil {
		log.Printf("Could not read client certificates: %v\n", err)
		return nil
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Printf("Could not append client certificates: %v\n", err)
		return nil
	}
	return caCertPool
}

func clientIP(r *http.Request) string {
	// 1. Try Forwarded (RFC 7239)
	if ip := fromForwarded(r); ip != "" {
		return ip
	}

	// 2. Try X-Forwarded-For
	if ip := fromXFF(r); ip != "" {
		return ip
	}

	// 3. Fallback to RemoteAddr
	if ip := fromRemoteAddr(r); ip != "" {
		return ip
	}

	return ""
}

func fromForwarded(r *http.Request) string {
	values := r.Header.Values("Forwarded")
	if len(values) == 0 {
		return ""
	}

	combined := cleanUntrustedString(strings.Join(values, ","))
	entries := strings.Split(combined, ",")

	for _, entry := range entries {
		parts := strings.Split(entry, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(strings.ToLower(p), "for=") {
				v := strings.TrimPrefix(p, "for=")
				v = strings.Trim(v, "\"") // remove quotes
				v = strings.Trim(v, "[]") // remove IPv6 brackets

				if net.ParseIP(v) != nil {
					return v
				}
			}
		}
	}
	return ""
}

func fromXFF(r *http.Request) string {
	xff := cleanUntrustedString(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return ""
	}

	parts := strings.Split(xff, ",")
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func fromRemoteAddr(r *http.Request) string {
	ip, _, err := net.SplitHostPort(cleanUntrustedString(r.RemoteAddr))
	if err == nil && net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func hasAccess(config configuration, r *http.Request) bool {

	// IP based Access control
	// Satisfy gosec by using clean again
	remoteAddr := cleanUntrustedString(clientIP(r))
	if config.debug {
		log.Printf("Remote IP address is: %s\n", remoteAddr)
	}
	cpos := strings.LastIndex(remoteAddr, ":")
	if cpos != -1 {
		remoteAddr = remoteAddr[:cpos]
	}
	hasBrackets, _ := regexp.MatchString("^\\[.*\\]$", remoteAddr)
	if hasBrackets {
		remoteAddr = remoteAddr[1 : len(remoteAddr)-1]
	}
	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		log.Printf("Invalid IP address: %s\n", remoteAddr)
		return false
	}

	matchRemote := false
	ipos1 := -1
	for {
		ipos2 := strings.Index(config.wrapperCidr[ipos1+1:], "|")
		if ipos2 < 0 {
			ipos2 = len(config.wrapperCidr) - ipos1 - 1
		}
		cidrStr := config.wrapperCidr[ipos1+1 : ipos1+1+ipos2]
		ipos1 = ipos1 + 1 + ipos2
		isNeg := strings.Index(cidrStr, "!") == 0
		hasSlash := strings.Contains(cidrStr, "/")
		if isNeg {
			cidrStr = cidrStr[1:]
		}
		if !hasSlash {
			cidrStr = cidrStr + "/32"
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			log.Printf("Remote IP: Cannot parse cidr: %s\n", cidrStr)
		} else {
			remoteIP := net.ParseIP(remoteAddr)
			matchRemote = cidr.Contains(remoteIP)
			if matchRemote {
				if isNeg {
					if config.debug {
						log.Printf("Remote IP: %s does not match !%s\n", remoteIP, cidrStr)
					}
					matchRemote = false
				} else {
					if config.debug {
						log.Printf("Remote IP: %s matches %s\n", remoteIP, cidrStr)
					}
					matchRemote = true
					break
				}
			} else if isNeg {
				if config.debug {
					log.Printf("Remote IP: %s matches !%s\n", remoteIP, cidrStr)
				}
				matchRemote = true
				break
			} else {
				if config.debug {
					log.Printf("Remote IP: %s does not match %s\n", remoteIP, cidrStr)
				}
				matchRemote = false
			}
		}
		if ipos1 == len(config.wrapperCidr) {
			break
		}
	}

	isMatch, _ := regexp.MatchString(config.wrapperFilter, remoteAddr)
	if isMatch && config.debug {
		log.Printf("Remote IP: %s matches %s\n", remoteAddr, config.wrapperFilter)
	}
	if !matchRemote && !isMatch {
		if config.debug {
			log.Printf("Remote IP: %s does not match cidr: %s\n", remoteAddr, config.wrapperCidr)
			log.Printf("Remote IP: %s does not match filter: %s\n", remoteAddr, config.wrapperFilter)
		}
		return false
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCert := r.TLS.PeerCertificates[0]
		if config.debug {
			subject := cleanUntrustedString(clientCert.Subject.String())
			issuer := cleanUntrustedString(clientCert.Issuer.String())
			log.Printf("Client Certificate Subject: %s\n", subject)
			log.Printf("Client Certificate Issuer: %s\n", issuer)
		}
	} else {
		if config.debug {
			log.Println("No client certificate provided.")
		}
		return false
	}
	return true
}

// Custom service handler function
func serviceHandler(config configuration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle the request
		tP := cleanUntrustedString(r.URL.Path)
		if tP != "/clamd/" && tP != "/clamd" {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		if !hasAccess(config, r) {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		contentType := cleanUntrustedString(r.Header.Get("Content-Type"))

		// Check the content type
		if contentType != "application/json" {
			log.Printf("Received content type: %s", cleanUntrustedString(contentType))
			http.Error(w, "403 Forbidden received unsupported content type", http.StatusForbidden)
			return
		}

		tM := cleanUntrustedString(r.Method)
		if tM != http.MethodPut {
			log.Printf("Received method type: %s", cleanUntrustedString(r.Method))
			http.Error(w, "403 Forbidden received unsupported method", http.StatusForbidden)
			return
		}

		//requestDump, err0 := httputil.DumpRequest(r, true)
		//if err0 != nil {
		//	log.Printf("request dump failed: %v\n", err)
		//}
		//log.Printf("Request: %s", requestDump)

		// Decode the JSON body
		var data clamdData
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&data)
		if err != nil {
			log.Printf("decode error: %v\n", err)
			http.Error(w, "Internal Server Error: Could not decode json data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Decode the Base64 string
		decodedBytes, err := base64.StdEncoding.DecodeString(data.Data)
		if err != nil {
			log.Println("Error decoding Base64 string:", err)
			return
		}

		if !allowedCommands[data.Command] {
			log.Printf("Command not allowed: %s\n", data.Command)
			http.Error(w, "403 Forbidden Command not allowed", http.StatusForbidden)
			return
		}

		if data.Size != int64(len(decodedBytes)) {
			log.Printf("Invalid Data Size: %d/%d\n", data.Size, len(decodedBytes))
			http.Error(w, "Internal Server Error: Invalid Data Size", http.StatusInternalServerError)
			return
		}

		client := clamd.NewClamd(config.clamdSocketPath)
		if config.debug {
			log.Printf("Received command: %s\n", data.Command)
		}
		var resultChan chan *clamd.ScanResult
		switch data.Command {
		case "PING":
			err = client.Ping()
			if err != nil {
				log.Printf("Could not open clamd scanner %v\n", err)
				http.Error(w, "Internal Server Error: Could not open clamd scanner: "+err.Error(), http.StatusInternalServerError)
				return
			}
			response := clamdResponseData{
				Message: "PONG",
				Status:  clamd.RES_OK,
			}
			// Set the content type to application/json
			w.Header().Set("Content-Type", "application/json")

			// Write the status code (200 OK)
			w.WriteHeader(http.StatusOK)

			// Encode the response data to JSON and send it
			if err := json.NewEncoder(w).Encode(response); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				http.Error(w, "Internal Server Error: Failed to encode response: "+err.Error(), http.StatusInternalServerError)
				return
			}
		case "VERSION":
			resultChan, err = client.Version()
			if err != nil {
				log.Printf("Could not open clamd scanner %v\n", err)
				http.Error(w, "Internal Server Error: Could not open clamd scanner: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// Read and print scan results
			for result := range resultChan {
				if config.debug {
					log.Printf("Clamd scan result: Raw: %s\n", result.Raw)
				}
				response := clamdResponseData{
					Message: result.Raw,
					Status:  clamd.RES_OK,
				}
				// Set the content type to application/json
				w.Header().Set("Content-Type", "application/json")

				// Write the status code (200 OK)
				w.WriteHeader(http.StatusOK)

				// Encode the response data to JSON and send it
				if err := json.NewEncoder(w).Encode(response); err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					http.Error(w, "Internal Server Error: Failed to encode response: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
		default:
			readPipe, writePipe := io.Pipe()

			go func() {
				defer func() { _ = writePipe.Close() }()
				_, err := writePipe.Write(decodedBytes)
				if err != nil {
					log.Printf("Could not write to clamd scanner %v\n", err)
				}
			}()

			resultChan, err = client.ScanStream(readPipe, make(chan bool))
			if err != nil {
				log.Printf("Could not open clamd scanner %v\n", err)
				http.Error(w, "Internal Server Error: Could not open clamd scanner: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Read and print scan results
			for result := range resultChan {
				if config.debug {
					log.Printf("Clamd scan result: Status:%s Raw: %s\n", result.Status, result.Raw)
				}
				//RES_OK          = "OK"           // No virus found
				//RES_FOUND       = "FOUND"        // Virus or malware detected
				//RES_ERROR       = "ERROR"        // General error during scanning
				//RES_PARSE_ERROR = "PARSE ERROR"  // Error parsing the response or input
				response := clamdResponseData{
					Message: result.Description,
					Status:  result.Status,
				}
				// Set the content type to application/json
				w.Header().Set("Content-Type", "application/json")

				// Write the status code (200 OK)
				w.WriteHeader(http.StatusOK)

				// Encode the response data to JSON and send it
				if err := json.NewEncoder(w).Encode(response); err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					http.Error(w, "Internal Server Error: Failed to encode response: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}

	}
}
