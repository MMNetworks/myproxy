package viruscheck

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dutchcoders/go-clamd"
	"io"
	"myproxy/logging"
	"myproxy/readconfig"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type ClamdStruct struct {
	clamd  *clamd.Clamd // embedded, so you can call methods directly
	https  bool
	client *http.Client
}

type clamdRequestData struct {
	Command string `json:"command"`
	Size    int64  `json:"size"`
	Data    string `json:"data"`
}

type clamdResponseData struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

func SetupClamd(connection string) (*ClamdStruct, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), 0)
	var clamdStruct *ClamdStruct
	sessionNo := int64(0)
	prefix := "https://"

	clamdStruct = &ClamdStruct{
		https:  false,
		clamd:  nil,
		client: nil,
	}

	if strings.HasPrefix(readconfig.Config.Clamd.Connection, prefix) {
		var serverName string

		clamdStruct.https = true

		index := strings.Index(readconfig.Config.Clamd.Connection, prefix)
		// Calculate the start position for the substring
		start := index + len(prefix)
		end := strings.Index(readconfig.Config.Clamd.Connection[start:], "/")
		if end == -1 {
			end = len(readconfig.Config.Clamd.Connection)
		}
		serverAddr := readconfig.Config.Clamd.Connection[start : end-1]

		var rootCAs *x509.CertPool
		if readconfig.Config.Clamd.CAfile != "insecure" {
			// Load system roots + optional CA bundle
			rootCAs, _ = x509.SystemCertPool()
			if caPem, err := os.ReadFile(readconfig.Config.Clamd.CAfile); err == nil {
				rootCAs.AppendCertsFromPEM(caPem)
			}
		}

		// Client cert for mTLS
		cert, err := tls.LoadX509KeyPair(readconfig.Config.Clamd.Certfile, readconfig.Config.Clamd.Keyfile)
		if err != nil {
			logging.Printf("ERROR", "SetupClamd: SessionID:%d Could not read client cert or key file %s/%s: %v\n", sessionNo, readconfig.Config.Clamd.Certfile, readconfig.Config.Clamd.Keyfile, err)
			return nil, err
		}

		ip := net.ParseIP(serverAddr)
		if ip != nil {
			serverNames, err := net.LookupAddr(serverAddr)
			if err != nil {
				logging.Printf("ERROR", "SetupClamd: SessionID:%d Could not convert IP %s to name: %v\n", sessionNo, serverAddr, err)
				return nil, err
			}
			// Don't expect multiple records for reverse DNS lookup
			serverName = serverNames[0]
		}
		var tlsConf *tls.Config
		if readconfig.Config.Clamd.CAfile == "insecure" {
			// Replace the TLSClientConfig
			tlsConf = &tls.Config{
				InsecureSkipVerify: true, // Skip certificate verification
				Certificates:       []tls.Certificate{cert},
				ServerName:         serverName,
				MinVersion:         tls.VersionTLS12,
			}
		} else {
			tlsConf = &tls.Config{
				RootCAs:      rootCAs,
				Certificates: []tls.Certificate{cert},
				ServerName:   serverName,
				MinVersion:   tls.VersionTLS12,
			}
		}

		// Create an HTTP client with the TLS configuration and keep-alive settings
		transport := &http.Transport{
			TLSClientConfig: tlsConf,
			IdleConnTimeout: 30 * time.Second, // Keep connections alive for 30 seconds
		}

		clamdStruct.client = &http.Client{Transport: transport}

	} else {
		clamdStruct.clamd = clamd.NewClamd(connection)
	}
	return clamdStruct, nil
}

func clamdRequest(sessionNo int64, client *http.Client, url string, body []byte) (string, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		logging.Printf("ERROR", "clamdRequest: SessionID:%d Could not create new request: %v\n", sessionNo, err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json") // Set the content type

	resp, err := client.Do(req)
	if err != nil {
		logging.Printf("ERROR", "clamdRequest: SessionID:%d Could not send request: %v\n", sessionNo, err)
		return "", err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Printf("ERROR", "clamdRequest: SessionID:%d Could not read response body: %v\n", sessionNo, err)
		return "", err
	}

	if len(responseBody) > 0 && responseBody[len(responseBody)-1] == '\n' {
		// Remove the last character
		responseBody = responseBody[:len(responseBody)-1]
	}

	if resp.StatusCode != http.StatusOK {
		logging.Printf("ERROR", "clamdRequest: SessionID:%d Error accessing clamd server: %s\n", sessionNo, responseBody)
		return "", errors.New(string(responseBody))
	}

	return string(responseBody), nil
}

func HasVirus(sessionNo int64, clamdStruct *ClamdStruct, data []byte) (string, bool) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), sessionNo)

	if !readconfig.Config.Clamd.Enable || clamdStruct == nil {
		return "", false
	}

	if clamdStruct.https {
		//
		// embedded TLS based client/server
		//

		encodedData := base64.StdEncoding.EncodeToString(data)

		request := clamdRequestData{
			Command: "INSTREAM",
			Size:    int64(len(data)),
			Data:    encodedData,
		}

		// Marshal the user struct to JSON
		requestBody, err := json.Marshal(request)
		if err != nil {
			logging.Printf("ERROR", "HasVirus: SessionID:%d Could not create json data: %v\n", sessionNo, err)
			if readconfig.Config.Clamd.BlockOnError {
				return "internal error", true
			} else {
				return "", false
			}
		}

		strResult, err := clamdRequest(sessionNo, clamdStruct.client, readconfig.Config.Clamd.Connection, []byte(requestBody))
		if err != nil {
			logging.Printf("ERROR", "HasVirus: SessionID:%d Could not communicate to clamd scanner: %v\n", sessionNo, err)
			if readconfig.Config.Clamd.BlockOnError {
				return "internal error", true
			} else {
				return "", false
			}
		}

		logging.Printf("DEBUG", "HasVirus: SessionID:%d Received response: %s\n", sessionNo, strResult)
		var response clamdResponseData
		err = json.Unmarshal([]byte(strResult), &response)
		if err != nil {
			logging.Printf("ERROR", "HasVirus: SessionID:%d Could not decode clamd response: %v\n", sessionNo, err)
			if readconfig.Config.Clamd.BlockOnError {
				return "internal error", true
			} else {
				return "", false
			}
		}

		if response.Status == "FOUND" {
			return response.Message, true
		}
		return "", false
	} else {
		//
		// Standard dutchcoders go-clamd
		//
		client := clamdStruct.clamd

		logging.Printf("DEBUG", "HasVirus: SessionID:%d Write response to clamd: %d bytes\n", sessionNo, len(data))
		readPipe, writePipe := io.Pipe()

		go func() {
			defer writePipe.Close()
			_, err := writePipe.Write(data)
			if err != nil {
				logging.Printf("ERROR", "HasVirus: SessionID:%d Could not write to clamd scanner: %v\n", sessionNo, err)
			}
		}()

		resultChan, err := client.ScanStream(readPipe, make(chan bool))
		if err != nil {
			logging.Printf("ERROR", "HasVirus: SessionID:%d Could not open clamd scanner: %v\n", sessionNo, err)
		}

		logging.Printf("DEBUG", "HasVirus: SessionID:%d Get results from clamd\n", sessionNo)
		// Read and print scan results
		for result := range resultChan {
			logging.Printf("DEBUG", "HasVirus: SessionID:%d Clamd scan result: Status:%s Raw: %s\n", sessionNo, result.Status, result.Raw)
			//RES_OK          = "OK"           // No virus found
			//RES_FOUND       = "FOUND"        // Virus or malware detected
			//RES_ERROR       = "ERROR"        // General error during scanning
			//RES_PARSE_ERROR = "PARSE ERROR"  // Error parsing the response or input
			if result.Status == clamd.RES_FOUND {
				return result.Description, true
			}
		}
		return "", false
	}
}
