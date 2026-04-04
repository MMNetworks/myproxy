// Package readconfig reads and interprets configuration file
package readconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
	"myproxy/logging"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

var versionMap = map[string]uint16{
	//	"SSL30": tls.VersionSSL30,
	"TLS10": tls.VersionTLS10,
	"TLS11": tls.VersionTLS11,
	"TLS12": tls.VersionTLS12,
	"TLS13": tls.VersionTLS13,
}

var curveMap = map[string]tls.CurveID{}

var cipherMap = map[string]uint16{}

func init() {
	// If curveMapExtra is nil, nothing happens
	for k, v := range curveMapExtra {
		curveMap[k] = v
	}
	// set cipher map
	for _, cs := range tls.CipherSuites() {
		cipherMap[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		cipherMap[cs.Name] = cs.ID
	}
}

// Config holds all configuration values
var Config *Schema

// Used by interface to retrieve logging configuration

// LogLevel returns log level
func (c *Schema) LogLevel() string { return c.Logging.Level }

// LogTrace returns trace value
func (c *Schema) LogTrace() bool { return c.Logging.Trace }

// LogFile returns log file name
func (c *Schema) LogFile() string { return c.Logging.File }

// AccessFile returns accesslog name
func (c *Schema) AccessFile() string { return c.Logging.AccessLog }

// MilliSeconds returns milliseconds value
func (c *Schema) MilliSeconds() bool { return c.Logging.MilliSeconds }

// TLSConfig defines TLS values
// use `yaml:""` struct tag to parse fields name with
// kebabcase, snakecase, and camelcase fields
type TLSConfig struct {
	CAbundle       string   `yaml:"cabundle"`
	MinVersion     string   `yaml:"minversion"`
	MaxVersion     string   `yaml:"maxversion"`
	CurveIDs       []string `yaml:"curveid"`
	CipherIDs      []string `yaml:"cipherid"`
	ClientKey      string   `yaml:"clientkey"`
	ClientCert     string   `yaml:"clientcert"`
	ClientKeyfile  string   `yaml:"clientkeyfile"`
	ClientCertfile string   `yaml:"clientcertfile"`
	ServerKey      string   `yaml:"serverkey"`
	ServerCert     string   `yaml:"servercert"`
	ServerKeyfile  string   `yaml:"serverkeyfile"`
	ServerCertfile string   `yaml:"servercertfile"`
}

// PAC structure
type PAC struct {
	Type      string `yaml:"type"`
	File      string `yaml:"file"`
	URL       string `yaml:"url"`
	Proxy     string `yaml:"proxy"`
	CacheTime int    `yaml:"cachetime"`
}

// Listen structure
type Listen struct {
	IP                string    `yaml:"ip"`
	Port              string    `yaml:"port"`
	TLS               bool      `yaml:"tls"`
	TLSConfig         TLSConfig `yaml:"tlsconfig"`
	ReadHeaderTimeout int       `yaml:"readheadertimeout"`
	ReadTimeout       int       `yaml:"readtimeout"`
	WriteTimeout      int       `yaml:"writetimeout"`
	IdleTimeout       int       `yaml:"idletimeout"`
	TLSConf           *tls.Config
}

// Logging structure
type Logging struct {
	Level        string `yaml:"level"`
	File         string `yaml:"file"`
	AccessLog    string `yaml:"accesslog"`
	Trace        bool   `yaml:"trace"`
	MilliSeconds bool   `yaml:"milliseconds"`
}

// Connection structure
type Connection struct {
	ReadTimeout  int       `yaml:"readtimeout"`
	DNSTimeout   int       `yaml:"dnstimeout"`
	FallbackTime *int      `yaml:"fallbackdelay"`
	IPv4         *bool     `yaml:"ipv4"`
	IPv6         *bool     `yaml:"ipv6"`
	Timeout      int       `yaml:"timeout"`
	Keepalive    int       `yaml:"keepalive"`
	DNSServers   []string  `yaml:"dnsservers"`
	TLSConfig    TLSConfig `yaml:"tlsconfig"`
	TLSConf      *tls.Config
}

// WSRule structure
type WSRule struct {
	IP      string `yaml:"ip"`
	Client  string `yaml:"client"`
	Regex   string `yaml:"regex"`
	Timeout int    `yaml:"timeout"`
}

// Websocket structure
type Websocket struct {
	Mu               sync.Mutex
	MaxPayloadLength int      `yaml:"maxplength"`
	Timeout          int      `yaml:"timeout"`
	Rules            []WSRule `yaml:"rules"`
	InitialRules     []WSRule
	RulesFile        string `yaml:"rulesfile"`
}

// FTP structure
type FTP struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// MitmRule structure
type MitmRule struct {
	IP        string    `yaml:"ip"`
	Client    string    `yaml:"client"`
	Regex     string    `yaml:"regex"`
	TLSConfig TLSConfig `yaml:"tlsconfig"`
	TLSConf   *tls.Config
}

// MITM structure
type MITM struct {
	Mu           sync.Mutex
	Enable       bool       `yaml:"enable"`
	TLSConfig    TLSConfig  `yaml:"tlsconfig"`
	Rules        []MitmRule `yaml:"rules"`
	InitialRules []MitmRule
	RulesFile    string `yaml:"rulesfile"`
	TLSConf      *tls.Config
}

// WiresharkRule structure
type WiresharkRule struct {
	IP string `yaml:"ip"`
}

// Wireshark structure
type Wireshark struct {
	Mu                sync.Mutex
	Enable            bool            `yaml:"enable"`
	UnmaskedWebsocket bool            `yaml:"unmaskedwebsocket"`
	IP                string          `yaml:"ip"`
	Port              string          `yaml:"port"`
	Rules             []WiresharkRule `yaml:"rules"`
	InitialRules      []WiresharkRule
	RulesFile         string `yaml:"rulesfile"`
}

// Clamd structure
type Clamd struct {
	Enable       bool      `yaml:"enable"`
	Block        bool      `yaml:"block"`
	BlockOnError bool      `yaml:"blockonerror"`
	TLSConfig    TLSConfig `yaml:"tlsconfig"`
	Connection   string    `yaml:"connection"`
	TLSConf      *tls.Config
}

// Proxy structure
type Proxy struct {
	Authentication []string `yaml:"authentication"`
	NtlmDomain     string   `yaml:"NTLMDomain"`
	NtlmUser       string   `yaml:"NTLMUser"`
	NtlmPass       string   `yaml:"NTLMPass"`
	KerberosConfig string   `yaml:"KRBConfig"`
	KerberosDomain string   `yaml:"KRBDomain"`
	KerberosUser   string   `yaml:"KRBUser"`
	KerberosCache  string   `yaml:"KRBCache"`
	KerberosPass   string   `yaml:"KRBPass"`
	BasicUser      string   `yaml:"BasicUser"`
	BasicPass      string   `yaml:"BasicPass"`
	LocalBasicUser string   `yaml:"LocalBasicUser"`
	LocalBasicHash string   `yaml:"LocalBasicHash"`
}

// Schema structure
type Schema struct {
	PAC        PAC        `yaml:"pac"`
	Proxy      Proxy      `yaml:"proxy"`
	Listen     Listen     `yaml:"listen"`
	Logging    Logging    `yaml:"logging"`
	Connection Connection `yaml:"connection"`
	Websocket  Websocket  ` yaml:"websocket"`
	FTP        FTP        `yaml:"ftp"`
	MITM       MITM       `yaml:"mitm"`
	Wireshark  Wireshark  `yaml:"wireshark"`
	Clamd      Clamd      `yaml:"clamd"`
}

var msec bool

func printf(level string, format string, a ...any) {
	message := fmt.Sprintf(format, a...)
	formatString := time.RFC1123
	if msec {
		formatString = "Mon, 02 Jan 2006 15:04:05.000 MST"
	}
	timeStamp := time.Now().Format(formatString)
	_, _ = fmt.Printf("%s %s: %s", timeStamp, level, message)
}

func getCallerName(level int) string {
	// level=0 -> callerName
	// level=1 -> the function that called callerName
	// level=2 -> the caller of that function
	// level=3 -> the caller of that function
	pc, _, _, ok := runtime.Caller(level)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}

	full := fn.Name()
	for i := strings.LastIndex(full, "."); i != -1; {
		return strings.TrimSuffix(full[i+1:], "-fm")
	}
	return strings.TrimSuffix(full, "-fm")
}

func setTLSConfig(readTLSConfig *TLSConfig, server bool) (*tls.Config, error) {
	var tlsConfig *tls.Config
	var skipVerify bool

	config := getCallerName(2)
	customPool, err := x509.SystemCertPool()
	if err != nil {
		logging.Printf("ERROR", "setTLSConfig: Could not read system certificate pool for %s: %v\n", config, err)
		return nil, err
	}
	if readTLSConfig.CAbundle == "insecure" {
		logging.Printf("WARNING", "setTLSConfig: TLS certificate verification DISABLED for %s - vulnerable to MITM attacks! Only use in trusted environments.\n", config)
		skipVerify = true
	}
	if readTLSConfig.CAbundle != "" && readTLSConfig.CAbundle != "insecure" {
		fileName := readTLSConfig.CAbundle
		customPool = x509.NewCertPool()
		if strings.HasPrefix(readTLSConfig.CAbundle, "+") {
			fileName = readTLSConfig.CAbundle[1:]
			logging.Printf("DEBUG", "setTLSConfig: Add certificate bundle %s to system bundle\n", fileName)
			customPool, err = x509.SystemCertPool()
			if err != nil {
				logging.Printf("ERROR", "setTLSConfig: Could not read system certificate pool for %s: %v\n", config, err)
				return nil, err
			}
		}
		caFilepath, err := filepath.Abs(fileName)
		if err != nil {
			logging.Printf("ERROR", "setTLSConfig: Getting file %s for %s: %v\n", readTLSConfig.CAbundle, config, err)
			return nil, err
		}
		_, err = os.Stat(caFilepath)
		if err != nil {
			return nil, err
		}

		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		caCert, err := os.ReadFile(caFilepath)
		if err != nil {
			logging.Printf("ERROR", "setTLSConfig: Could not read CA bundle %s for %s: %v\n", readTLSConfig.CAbundle, config, err)
			return nil, err
		}
		ok := customPool.AppendCertsFromPEM(caCert)
		if !ok {
			logging.Printf("ERROR", "setTLSConfig: Failed to append custom CA bundle for %s\n", config)
			return nil, errors.New("could not append custom CA bundle")
		}
	}
	// #nosec G402 -- intentionally disabled
	if server {
		// TLS on server to verify client
		tlsConfig = &tls.Config{
			ClientCAs:          customPool,
			ClientAuth:         tls.RequestClientCert, // request client cert
			InsecureSkipVerify: skipVerify,            // Skip certificate verification
			// ClientAuth: tls.RequireAndVerifyClientCert, // enforce client cert
		}
	} else {
		// TLS on client to verify server
		tlsConfig = &tls.Config{
			RootCAs:            customPool,
			InsecureSkipVerify: skipVerify, // Skip certificate verification
		}
	}
	if readTLSConfig.MinVersion != "" {
		id, ok := versionMap[readTLSConfig.MinVersion]
		if !ok {
			logging.Printf("WARNING", "setTLSConfig: unknown tls version for %s: %s\n", config, readTLSConfig.MinVersion)
		} else {
			tlsConfig.MinVersion = id
		}
	} else {
		tlsConfig.MinVersion = tls.VersionTLS12
		logging.Printf("INFO", "setTLSConfig: set tls version for %s to TLS12\n", config)
	}
	if readTLSConfig.MaxVersion != "" {
		id, ok := versionMap[readTLSConfig.MaxVersion]
		if !ok {
			logging.Printf("WARNING", "setTLSConfig: unknown tls version for %s: %s\n", config, readTLSConfig.MaxVersion)
		} else {
			tlsConfig.MaxVersion = id
		}
	}
	if len(readTLSConfig.CurveIDs) > 0 {
		tlsConfig.CurvePreferences = []tls.CurveID{}
		for _, name := range readTLSConfig.CurveIDs {
			id, ok := curveMap[name]
			if !ok {
				logging.Printf("WARNING", "soretTLSConfig: unknown curve ID for %s: %s\n", config, name)
			} else {
				tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, id)
			}
		}
	}
	if len(readTLSConfig.CipherIDs) > 0 {
		tlsConfig.CipherSuites = []uint16{}
		for _, name := range readTLSConfig.CipherIDs {
			id, ok := cipherMap[name]
			if !ok {
				logging.Printf("WARNING", "setTLSConfig: unknown cipher ID for %s: %s\n", config, name)
			} else {
				tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, id)
			}
		}
	}
	return tlsConfig, nil
}

func readLoggingConfig(configOut *Schema) error {

	msec = configOut.Logging.MilliSeconds

	if configOut.Logging.Level == "" {
		configOut.Logging.Level = "info"
	}

	if configOut.Logging.File == "" {
		configOut.Logging.File = "stdout"
	} else if strings.ToUpper(configOut.Logging.File) == "SYSLOG" || strings.ToUpper(configOut.Logging.File) == "EVENTLOG" {
		configOut.Logging.File = strings.ToUpper(configOut.Logging.File)
	} else if strings.ToUpper(configOut.Logging.File) != "STDOUT" {
		var logFile *os.File
		logFilepath, err := filepath.Abs(configOut.Logging.File)
		if err != nil {
			printf("ERROR", "readLoggingConfig: Getting file %s: %v\n", configOut.Logging.File, err)
			return err
		}
		configOut.Logging.File = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.File)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR, 0600)
				if err != nil {
					printf("ERROR", "readLoggingConfig: logfile %s not writeable\n", configOut.Logging.File)
					return err
				}
				printf("WARNING", "readLoggingConfig: logfile %s exists. Will append \n", configOut.Logging.File)

				defer func() { _ = logFile.Close() }()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				printf("ERROR", "readLoggingConfig: logfile %s cannot be created\n", configOut.Logging.File)
				return err
			}
			printf("INFO", "readLoggingConfig: logfile %s created.\n", configOut.Logging.File)

			defer func() { _ = logFile.Close() }()
		}
	}

	if configOut.Logging.AccessLog == "" {
		configOut.Logging.AccessLog = "stdout"
	} else if strings.ToUpper(configOut.Logging.AccessLog) == "SYSLOG" || strings.ToUpper(configOut.Logging.AccessLog) == "EVENTLOG" {
		configOut.Logging.AccessLog = strings.ToUpper(configOut.Logging.AccessLog)
	} else if strings.ToUpper(configOut.Logging.AccessLog) != "STDOUT" {
		var logFile *os.File
		logFilepath, err := filepath.Abs(configOut.Logging.AccessLog)
		if err != nil {
			printf("ERROR", "readLoggingConfig: Getting file %s: %v\n", configOut.Logging.AccessLog, err)
			return err
		}
		configOut.Logging.AccessLog = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.AccessLog)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR, 0600)
				if err != nil {
					printf("ERROR", "readLoggingConfig: access logfile %s not writeable\n", configOut.Logging.AccessLog)
					return err
				}
				printf("WARNING", "readLoggingConfig: access logfile %s exists. Will append \n", configOut.Logging.AccessLog)

				defer func() { _ = logFile.Close() }()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				printf("ERROR", "readLoggingConfig: access logfile %s cannot be created\n", configOut.Logging.AccessLog)
				return err
			}
			printf("INFO", "readLoggingConfig: access logfile %s created.\n", configOut.Logging.AccessLog)

			defer func() { _ = logFile.Close() }()
		}
	}

	printf("INFO", "readLoggingConfig: Read log config.\n")
	printf("INFO", "readLoggingConfig: Start log processor.\n")
	// After logging config check start log processor
	go logging.LogProcessor(configOut)
	// Give Processor goroutine some time for setup
	time.Sleep(2 * time.Second)
	printf("INFO", "readLoggingConfig: log processor started.\n")

	return nil
}

func readListenConfig(configOut *Schema) error {
	var err error
	if configOut.Listen.TLS && (configOut.Listen.TLSConfig.ServerKeyfile == "" || configOut.Listen.TLSConfig.ServerCertfile == "") {
		logging.Printf("ERROR", "readListenConfig: TLS requires Certfile and Keyfile file: %s/%s\n", configOut.Listen.TLSConfig.ServerCertfile, configOut.Listen.TLSConfig.ServerKeyfile)
		return errors.New("invalid TLS configuration")
	}
	if configOut.Listen.TLSConfig.ServerKeyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.Listen.TLSConfig.ServerKeyfile)
		if err != nil {
			logging.Printf("ERROR", "readListenConfig: Getting file %s: %v\n", configOut.Listen.TLSConfig.ServerKeyfile, err)
			return err
		}
		configOut.Listen.TLSConfig.ServerKeyfile = keyFilepath
	}
	if configOut.Listen.TLSConfig.ServerCertfile != "" {
		certFilepath, err := filepath.Abs(configOut.Listen.TLSConfig.ServerCertfile)
		if err != nil {
			logging.Printf("ERROR", "readListenConfig: Getting file %s: %v\n", configOut.Listen.TLSConfig.ServerCertfile, err)
			return err
		}
		configOut.Listen.TLSConfig.ServerCertfile = certFilepath
	}
	if configOut.Listen.TLSConfig.ClientKey != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ClientKey\n")
	}
	if configOut.Listen.TLSConfig.ClientCert != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ClientCert\n")
	}
	if configOut.Listen.TLSConfig.ClientKeyfile != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ClientKeyfile\n")
	}
	if configOut.Listen.TLSConfig.ClientCertfile != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ClientCertfile\n")
	}
	if configOut.Listen.TLSConfig.ServerKey != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ServerKey\n")
	}
	if configOut.Listen.TLSConfig.ServerCert != "" {
		logging.Printf("WARNING", "readListenConfig: Invalid TLS config ServerCert\n")
	}
	configOut.Listen.TLSConf, err = setTLSConfig(&configOut.Listen.TLSConfig, true)
	if err != nil {
		logging.Printf("ERROR", "readListenConfig: Could not set TLS config: %v\n", err)
		return err
	}

	if configOut.Listen.IP == "" {
		configOut.Listen.IP = "127.0.0.1"
	}
	if configOut.Listen.Port == "" {
		configOut.Listen.Port = "9080"
	}
	if configOut.Listen.IdleTimeout == 0 {
		configOut.Listen.IdleTimeout = 300
	}
	return nil
}

func readConnectionConfig(configOut *Schema) error {
	var err error

	if configOut.Connection.Timeout == 0 {
		configOut.Connection.Timeout = 5
	}
	if configOut.Connection.Keepalive == 0 {
		configOut.Connection.Keepalive = 10
	}
	if configOut.Connection.DNSTimeout == 0 {
		configOut.Connection.DNSTimeout = 2
	}
	if configOut.Connection.FallbackTime == nil {
		value := 300
		configOut.Connection.FallbackTime = &value
	}
	if configOut.Connection.IPv4 == nil {
		value := true
		configOut.Connection.IPv4 = &value
	}
	if configOut.Connection.IPv6 == nil {
		value := true
		configOut.Connection.IPv6 = &value
	}
	if !*configOut.Connection.IPv6 && !*configOut.Connection.IPv4 {
		logging.Printf("ERROR", "ReadConfig: Require IOV6 and/or IPV4 support\n")
		return errors.New("require ipv6 or ipv4")
	}
	if len(configOut.Connection.DNSServers) > 0 {
		for i := 0; i < len(configOut.Connection.DNSServers); i++ {
			_, _, err := net.SplitHostPort(configOut.Connection.DNSServers[i])
			if err != nil {
				configOut.Connection.DNSServers[i] = configOut.Connection.DNSServers[i] + ":53"
			}
		}
	}
	if configOut.Connection.TLSConfig.ClientKey != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ClientKey\n")
	}
	if configOut.Connection.TLSConfig.ClientCert != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ClientCert\n")
	}
	if configOut.Connection.TLSConfig.ClientKeyfile != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ClientKeyfile\n")
	}
	if configOut.Connection.TLSConfig.ClientCertfile != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ClientCertfile\n")
	}
	if configOut.Connection.TLSConfig.ServerKey != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ServerKey\n")
	}
	if configOut.Connection.TLSConfig.ServerCert != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ServerCert\n")
	}
	if configOut.Connection.TLSConfig.ServerKeyfile != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ServerKeyfile\n")
	}
	if configOut.Connection.TLSConfig.ServerCertfile != "" {
		logging.Printf("WARNING", "readConnectionConfig: Invalid TLS config ServerCertfile\n")
	}
	configOut.Connection.TLSConf, err = setTLSConfig(&configOut.Connection.TLSConfig, false)
	if err != nil {
		logging.Printf("ERROR", "readConnectionConfig: could not set TLS Config: %v\n", err)
		configOut.Connection.TLSConf = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return nil
}

func readPACConfig(configOut *Schema) error {
	if configOut.PAC.Type != "FILE" && configOut.PAC.Type != "URL" && configOut.PAC.Type != "" {
		logging.Printf("ERROR", "readPACConfig: Reading PAC type field: %s\n", configOut.PAC.Type)
		logging.Printf("ERROR", "readPACConfig: Only FILE and URL supported\n")
		return errors.New("wrong pac type")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File == "" {
		logging.Printf("ERROR", "readPACConfig: Reading PAC type FILE: %s\n", configOut.PAC.File)
		logging.Printf("ERROR", "readPACConfig: FILE needs a filename\n")
		return errors.New("pac file name missing")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File != "" {
		pacFilepath, err := filepath.Abs(configOut.PAC.File)
		if err != nil {
			logging.Printf("ERROR", "readPACConfig: Getting file %s: %v\n", configOut.PAC.File, err)
			return err
		}
		configOut.PAC.File = pacFilepath
		_, err = os.Stat(configOut.PAC.File)
		if errors.Is(err, os.ErrNotExist) || err != nil {
			logging.Printf("ERROR", "readPACConfig: Can not read PAC file %s\n", configOut.PAC.File)
			return err
		}
	}

	if configOut.PAC.Type == "URL" && configOut.PAC.URL == "" {
		logging.Printf("ERROR", "readPACConfig: Reading PAC type URL: %s\n", configOut.PAC.URL)
		logging.Printf("ERROR", "readPACConfig: URL needs a url\n")
		return errors.New("PAC URL missing")
	}
	return nil
}

func readAuthConfig(configOut *Schema) error {
	osType := runtime.GOOS

	for i, v := range configOut.Proxy.Authentication {
		if v != "ntlm" && v != "negotiate" && v != "basic" {
			logging.Printf("ERROR", "readAuthConfig: Reading authentication field: %d:%s\n", i+1, v)
			logging.Printf("ERROR", "readAuthConfig: Only ntln,negotiate and basic are supported\n")
			return errors.New("invalid authentication type")
		}
	}
	if osType != "windows" {
		if configOut.Proxy.NtlmUser != "" && configOut.Proxy.NtlmPass == "" {
			fmt.Printf("Enter NTLM Password for %s: ", configOut.Proxy.NtlmUser)
			// #nosec G115 (CWE-190) -- save
			fd := int(os.Stdin.Fd())
			bytePassword, err := term.ReadPassword(fd)
			if err != nil {
				logging.Printf("ERROR", "readAuthConfig: NTLM Password read error\n")
				return err
			}
			fmt.Printf("\n")
			configOut.Proxy.NtlmPass = string(bytePassword)
		}

		if configOut.Proxy.KerberosConfig != "" {
			kconfigFilepath, err := filepath.Abs(configOut.Proxy.KerberosConfig)
			if err != nil {
				logging.Printf("ERROR", "readAuthConfig: Getting file %s: %v\n", configOut.Proxy.KerberosConfig, err)
				return err
			}
			configOut.Proxy.KerberosConfig = kconfigFilepath
			_, err = os.Stat(configOut.Proxy.KerberosConfig)
			if errors.Is(err, os.ErrNotExist) || err != nil {
				logging.Printf("ERROR", "readAuthConfig: Can not read Kerberos config file %s\n", configOut.Proxy.KerberosConfig)
				return err
			}
		}

		if configOut.Proxy.KerberosUser != "" && configOut.Proxy.KerberosPass == "" && configOut.Proxy.KerberosCache == "" {
			fmt.Printf("Enter Kerberos Password for %s: ", configOut.Proxy.KerberosUser)
			// #nosec G115 (CWE-190) -- save
			fd := int(os.Stdin.Fd())
			bytePassword, err := term.ReadPassword(fd)
			if err != nil {
				logging.Printf("ERROR", "readAuthConfig: Kerberos Password read error\n")
				return err
			}
			fmt.Printf("\n")
			configOut.Proxy.KerberosPass = string(bytePassword)
		}
		if configOut.Proxy.KerberosCache != "" {
			ccacheFilepath, err := filepath.Abs(configOut.Proxy.KerberosCache)
			if err != nil {
				logging.Printf("ERROR", "readAuthConfig: Getting file %s: %v\n", configOut.Proxy.KerberosCache, err)
				return err
			}
			configOut.Proxy.KerberosCache = ccacheFilepath
		}
	} else {
		logging.Printf("INFO", "readAuthConfig: NTLM and Kerberos details are not used with SSPI\n")
	}

	if configOut.Proxy.BasicUser != "" && configOut.Proxy.BasicPass == "" {
		fmt.Printf("Enter Basic Password for %s: ", configOut.Proxy.BasicUser)
		// #nosec G115 (CWE-190) -- save
		fd := int(os.Stdin.Fd())
		bytePassword, err := term.ReadPassword(fd)
		if err != nil {
			logging.Printf("ERROR", "readAuthConfig: Basic  Password read error\n")
			return err
		}
		fmt.Printf("\n")
		configOut.Proxy.BasicPass = string(bytePassword)
	}
	return nil
}

func readMITMConfig(watcher *fsnotify.Watcher, configOut *Schema) error {
	if configOut.MITM.Enable {
		// Check all combinations
		switch {
		case
			configOut.MITM.TLSConfig.ServerKey == "" && configOut.MITM.TLSConfig.ServerKeyfile == "",
			configOut.MITM.TLSConfig.ServerCert == "" && configOut.MITM.TLSConfig.ServerCertfile == "",
			configOut.MITM.TLSConfig.ServerKey != "" && configOut.MITM.TLSConfig.ServerKeyfile != "",
			configOut.MITM.TLSConfig.ServerCert != "" && configOut.MITM.TLSConfig.ServerCertfile != "":
			return errors.New("invalid mitm certificate configuration")
		default:
		}
		var err error
		var keyFilepath string
		var certFilepath string
		if configOut.MITM.TLSConfig.ClientKey != "" {
			logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientKey\n")
		}
		if configOut.MITM.TLSConfig.ClientCert != "" {
			logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientCert\n")
		}
		if configOut.MITM.TLSConfig.ClientKeyfile != "" {
			logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientKeyfile\n")
		}
		if configOut.MITM.TLSConfig.ClientCertfile != "" {
			logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientCertfile\n")
		}
		if configOut.MITM.TLSConfig.ServerKeyfile != "" {
			keyFilepath, err = filepath.Abs(configOut.MITM.TLSConfig.ServerKeyfile)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Getting file %s: %v\n", configOut.MITM.TLSConfig.ServerKeyfile, err)
				return err
			}
		}
		if configOut.MITM.TLSConfig.ServerCertfile != "" {
			certFilepath, err = filepath.Abs(configOut.MITM.TLSConfig.ServerCertfile)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Getting file %s: %v\n", configOut.MITM.TLSConfig.ServerCertfile, err)
				return err
			}
		}
		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		buf, err := os.ReadFile(keyFilepath)
		if err != nil {
			logging.Printf("ERROR", "readMITMConfig: Could not read Keyfile file: %v\n", err)
			return err
		}
		configOut.MITM.TLSConfig.ServerKey = string(buf)
		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		buf, err = os.ReadFile(certFilepath)
		if err != nil {
			logging.Printf("ERROR", "readMITMConfig: Could not read Keyfile file: %v\n", err)
			return err
		}
		configOut.MITM.TLSConfig.ServerCert = string(buf)

		if configOut.MITM.RulesFile != "" {
			filePath, err := filepath.Abs(configOut.MITM.RulesFile)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Getting file %s: %v\n", configOut.MITM.RulesFile, err)
				return err
			}
			// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
			file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Could not read rules file %s: %v\n", filePath, err)
				return err
			}
			defer func() { _ = file.Close() }()

			decoder := yaml.NewDecoder(file)
			decoder.KnownFields(true)
			var fileRules []MitmRule
			err = decoder.Decode(&fileRules)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Decoding file %s: %v\n", filePath, err)
				return err
			}

			// Save initial rules
			configOut.MITM.InitialRules = make([]MitmRule, len(configOut.MITM.Rules))
			// Copy contents
			copy(configOut.MITM.InitialRules, configOut.MITM.Rules)

			logging.Printf("DEBUG", "readMITMConfig: read %d rules from myproxy config file\n", len(configOut.MITM.Rules))
			configOut.MITM.Rules = append(configOut.MITM.Rules, fileRules...)
			logging.Printf("DEBUG", "readMITMConfig: added %d rules from MITM rules file\n", len(fileRules))

			for n, rule := range configOut.MITM.Rules {
				logging.Printf("DEBUG", "readMITMConfig: set TLS config for rule %d \n", n+1)
				if rule.TLSConfig.ClientKey != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientKey\n")
				}
				if rule.TLSConfig.ClientCert != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientCert\n")
				}
				if rule.TLSConfig.ClientKeyfile != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientKeyfile\n")
				}
				if rule.TLSConfig.ClientCertfile != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ClientCertfile\n")
				}
				if rule.TLSConfig.ServerKey != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ServerKey\n")
				}
				if rule.TLSConfig.ServerCert != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ServerCert\n")
				}
				if rule.TLSConfig.ServerKeyfile != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ServerKeyfile\n")
				}
				if rule.TLSConfig.ServerCertfile != "" {
					logging.Printf("WARNING", "readMITMConfig: Invalid TLS config ServerCertfile\n")
				}
				rule.TLSConf, err = setTLSConfig(&rule.TLSConfig, false)
				if err != nil {
					logging.Printf("ERROR", "readMITMConfig: could not set TLS Config for rule %d, set to default: %v\n", n+1, err)
					rule.TLSConf = &tls.Config{MinVersion: tls.VersionTLS12}
				}
			}

			// Watch config file
			fileDir := filepath.Dir(filePath)
			//err = watcher.Add(filePath)
			//if err != nil {
			//	logging.Printf("ERROR", "readMITMConfig: Watching file %s: %v\n", filePath, err)
			//	return nil, err
			//}
			err = watcher.Add(fileDir)
			if err != nil {
				logging.Printf("ERROR", "readMITMConfig: Watching file %s: %v\n", fileDir, err)
				return err
			}
			logging.Printf("INFO", "readMITMConfig: Watching file %s\n", filePath)

		}

	}
	return nil
}

func readWiresharkConfig(watcher *fsnotify.Watcher, configOut *Schema) error {
	if configOut.Wireshark.IP == "" {
		configOut.Wireshark.IP = "127.0.0.1"
	}

	if configOut.Wireshark.Port == "" {
		configOut.Wireshark.Port = "19000"
	}

	if configOut.Wireshark.RulesFile != "" {
		filePath, err := filepath.Abs(configOut.Wireshark.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "readWiresharkConfig: Getting file %s: %v\n", configOut.Wireshark.RulesFile, err)
			return err
		}
		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
		if err != nil {
			logging.Printf("ERROR", "readWiresharkConfig: Could not read wireshark rules file %s: %v\n", configOut.Wireshark.RulesFile, err)
			return err
		}
		defer func() { _ = file.Close() }()

		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		var fileRules []WiresharkRule
		err = decoder.Decode(&fileRules)
		if err != nil {
			logging.Printf("ERROR", "readWiresharkConfig: Decoding file %s: %v\n", filePath, err)
			return err
		}

		// Save initial rules
		configOut.Wireshark.InitialRules = make([]WiresharkRule, len(configOut.Wireshark.Rules))
		// Copy contents
		copy(configOut.Wireshark.InitialRules, configOut.Wireshark.Rules)

		configOut.Wireshark.Rules = append(configOut.Wireshark.Rules, fileRules...)

		// Watch config file
		fileDir := filepath.Dir(filePath)
		//err = watcher.Add(filePath)
		//if err != nil {
		//	logging.Printf("ERROR", "readWiresharkConfig: Watching file %s: %v\n", filePath, err)
		//	return nil, err
		//}
		err = watcher.Add(fileDir)
		if err != nil {
			logging.Printf("ERROR", "readWiresharkConfig: Watching file %s: %v\n", fileDir, err)
			return err
		}
		logging.Printf("INFO", "readWiresharkConfig: Watching file %s\n", filePath)
	}

	return nil
}

func readWebsocketConfig(watcher *fsnotify.Watcher, configOut *Schema) error {

	if configOut.Websocket.Timeout == 0 {
		if configOut.Connection.ReadTimeout != 0 {
			configOut.Websocket.Timeout = configOut.Connection.ReadTimeout
		}
	}

	if configOut.Websocket.MaxPayloadLength == 0 {
		configOut.Websocket.MaxPayloadLength = 16 * 65535
	}

	if configOut.Websocket.RulesFile != "" {
		filePath, err := filepath.Abs(configOut.Websocket.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "readWebsocketConfig: Getting file %s: %v\n", configOut.Websocket.RulesFile, err)
			return err
		}
		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
		if err != nil {
			logging.Printf("ERROR", "readWebsocketConfig: Could not read rules file %s: %v\n", filePath, err)
			return err
		}
		defer func() { _ = file.Close() }()

		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		var fileRules []WSRule
		err = decoder.Decode(&fileRules)
		if err != nil {
			logging.Printf("ERROR", "readWebsocketConfig: Decoding file %s: %v\n", filePath, err)
			return err
		}

		// Save initial rules
		configOut.Websocket.InitialRules = make([]WSRule, len(configOut.Websocket.Rules))
		// Copy contents
		copy(configOut.Websocket.InitialRules, configOut.Websocket.Rules)

		configOut.Websocket.Rules = append(configOut.Websocket.Rules, fileRules...)
		// Watch config file
		fileDir := filepath.Dir(filePath)
		//err = watcher.Add(filePath)
		//if err != nil {
		//	logging.Printf("ERROR", "readWebsocketConfig: Watching file %s: %v\n", filePath, err)
		//	return nil, err
		//}
		err = watcher.Add(fileDir)
		if err != nil {
			logging.Printf("ERROR", "readWebsocketConfig: Watching file %s: %v\n", fileDir, err)
			return err
		}
		logging.Printf("INFO", "readWebsocketConfig: Watching file %s\n", filePath)
	}
	return nil
}

func readClamdConfig(configOut *Schema) error {
	var err error

	if configOut.Clamd.Connection == "" {
		configOut.Clamd.Connection = "unix:/var/run/clamav/clamd.ctl"
	}
	prefix := "tls:"
	if strings.HasPrefix(configOut.Clamd.Connection, prefix) {
		if configOut.Clamd.TLSConfig.ClientKey != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ClientKey\n")
		}
		if configOut.Clamd.TLSConfig.ClientCert != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ClientCert\n")
		}
		if configOut.Clamd.TLSConfig.ServerKey != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ServerKey\n")
		}
		if configOut.Clamd.TLSConfig.ServerCert != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ServerCert\n")
		}
		if configOut.Clamd.TLSConfig.ServerKeyfile != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ServerKeyfile\n")
		}
		if configOut.Clamd.TLSConfig.ServerCertfile != "" {
			logging.Printf("WARNING", "readClamdConfig: Invalid TLS config ServerCertfile\n")
		}
		if configOut.Clamd.TLSConfig.ClientCertfile == "" || configOut.Clamd.TLSConfig.ClientKeyfile == "" {
			return errors.New("missing client cert or key to authenticate")
		}
	}

	if configOut.Clamd.TLSConfig.ClientCertfile != "" {
		certFilepath, err := filepath.Abs(configOut.Clamd.TLSConfig.ClientCertfile)
		if err != nil {
			logging.Printf("ERROR", "readClamdConfig: Getting file %s: %v\n", configOut.Clamd.TLSConfig.ClientCertfile, err)
			return err
		}
		_, err = os.Stat(certFilepath)
		if err != nil {
			return err
		}
		configOut.Clamd.TLSConfig.ClientCertfile = certFilepath
	}
	if configOut.Clamd.TLSConfig.ClientKeyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.Clamd.TLSConfig.ClientKeyfile)
		if err != nil {
			logging.Printf("ERROR", "readClamdConfig: Getting file %s: %v\n", configOut.Clamd.TLSConfig.ClientKeyfile, err)
			return err
		}
		_, err = os.Stat(keyFilepath)
		if err != nil {
			return err
		}
		configOut.Clamd.TLSConfig.ClientKeyfile = keyFilepath
	}
	configOut.Clamd.TLSConf, err = setTLSConfig(&configOut.Clamd.TLSConfig, false)
	if err != nil {
		logging.Printf("ERROR", "readClamdConfig: could not set TLS Config: %v\n", err)
		return err
	}

	return nil
}

// ReadConfig reads values from yaml configuration file
func ReadConfig(configFilename string, watcher *fsnotify.Watcher) (*Schema, error) {

	filePath, err := filepath.Abs(configFilename)
	if err != nil {
		printf("ERROR", "Readconfig: Getting file %s, %v\n", configFilename, err)
		return nil, err
	}

	// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
	if err != nil {
		printf("ERROR", "Readconfig: opening file %s, %v\n", filePath, err)
		return nil, err
	}
	defer func() { _ = file.Close() }()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var configOut = Schema{}
	err = decoder.Decode(&configOut)

	if err != nil {
		printf("ERROR", "ReadConfig: decoding file %s: %v\n", filePath, err)
		return nil, err
	}

	err = readLoggingConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing logging configuration: %v\n", err)
		return nil, err
	}

	err = readListenConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing authentication configuration: %v\n", err)
		return nil, err
	}

	err = readConnectionConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing Connection configuration: %v\n", err)
		return nil, err
	}

	err = readPACConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing PAC configuration: %v\n", err)
		return nil, err
	}

	err = readAuthConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing authentication configuration: %v\n", err)
		return nil, err
	}

	err = readMITMConfig(watcher, &configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing MITM configuration: %v\n", err)
		return nil, err
	}

	err = readWiresharkConfig(watcher, &configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing Wireshark configuration: %v\n", err)
		return nil, err
	}

	err = readWebsocketConfig(watcher, &configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing Websocket configuration: %v\n", err)
		return nil, err
	}

	err = readClamdConfig(&configOut)
	if err != nil {
		printf("ERROR", "Readconfig: Failed processing Clamd configuration: %v\n", err)
		return nil, err
	}

	if configOut.FTP.Username == "" {
		configOut.FTP.Username = "anonymous"
	}
	if configOut.FTP.Password == "" {
		configOut.FTP.Password = "anonymous@myproxy"
	}

	go watchFiles(watcher, &configOut)

	return &configOut, nil
}

// openWithRetry tries to open a file with retries.
// It retries if the error is a Windows sharing violation.
func openWithRetry(filename string, flag int, perm os.FileMode) (*os.File, error) {

	var f *os.File
	var err error
	var maxRetries = 10
	var delay = 1 * time.Second
	const ERROR_SHARING_VIOLATION syscall.Errno = 32 // Windows error code

	for i := 1; i <= maxRetries; i++ {
		// #nosec G304 -- path comes from trusted, access controlled configuration; not user-controlled input
		f, err = os.OpenFile(filename, flag, perm)
		if err == nil {
			return f, nil
		}

		// Check if it's a sharing violation
		if pe, ok := err.(*os.PathError); ok {
			if runtime.GOOS == "windows" && pe.Err == ERROR_SHARING_VIOLATION {
				logging.Printf("ERROR", "openWithRetries: File %s is locked, retrying: %v\n", filename, err)
				time.Sleep(delay)
				continue
			} else if errors.Is(pe.Err, syscall.EBUSY) || errors.Is(pe.Err, syscall.EPERM) {
				logging.Printf("ERROR", "openWithRetries: File %s is locked, retrying: %v\n", filename, err)
				time.Sleep(delay)
				continue
			}
		}

		// Some other error — stop retrying
		return nil, err
	}

	return nil, fmt.Errorf("failed to open file after %d retries: %w", maxRetries, err)
}

func watchFiles(watcher *fsnotify.Watcher, configOut *Schema) {
	var MITMFilePath string
	var WebsocketFilePath string
	var WiresharkFilePath string
	var err error

	if configOut.MITM.RulesFile != "" {
		MITMFilePath, err = filepath.Abs(configOut.MITM.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "watchFiles: Getting file %s: %v\n", configOut.MITM.RulesFile, err)
		}
	}
	if configOut.Wireshark.RulesFile != "" {
		WiresharkFilePath, err = filepath.Abs(configOut.Wireshark.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "watchFiles: Getting file %s: %v\n", configOut.Wireshark.RulesFile, err)
		}
	}
	if configOut.Websocket.RulesFile != "" {
		WebsocketFilePath, err = filepath.Abs(configOut.Websocket.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "watchFiles: Getting file %s: %v\n", configOut.Websocket.RulesFile, err)
		}
	}

	go func() {
		for err := range watcher.Errors {
			if err != nil {
				logging.Printf("ERROR", "watchFiles: Error monitoring files: %v\n", err)
			}
		}
	}()

	logging.Printf("DEBUG", "watchFiles: Start Event Loop\n")
	for event := range watcher.Events {
		// logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
		if filepath.Clean(event.Name) == filepath.Clean(MITMFilePath) || filepath.Base(event.Name) == filepath.Base(MITMFilePath) {
			// Trigger reload on modification or replacement
			// Can happen multiple times in short time based on tol used to update file
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				file, err := openWithRetry(MITMFilePath, os.O_RDONLY, 0600)
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Could not read rules file %s: %v\n", MITMFilePath, err)
					continue
				}

				decoder := yaml.NewDecoder(file)
				decoder.KnownFields(true)
				var fileRules []MitmRule
				err = decoder.Decode(&fileRules)
				_ = file.Close()
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Decoding file %s: %v\n", MITMFilePath, err)
					continue
				}
				configOut.MITM.Mu.Lock()
				// Reset to Initial rules
				configOut.MITM.Rules = make([]MitmRule, len(configOut.MITM.InitialRules))
				// Copy contents
				logging.Printf("DEBUG", "watchFiles: read %d MITM rules from myproxy config file\n", len(configOut.MITM.Rules))
				copy(configOut.MITM.Rules, configOut.MITM.InitialRules)
				// Append new rules
				configOut.MITM.Rules = append(configOut.MITM.Rules, fileRules...)
				logging.Printf("DEBUG", "watchFiles: added %d MITM rules from MITM rules file\n", len(configOut.MITM.Rules))
				configOut.MITM.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from MITM rules file %s\n", MITMFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.MITM.Mu.Lock()
				// Reset to Initial rules
				configOut.MITM.Rules = make([]MitmRule, len(configOut.MITM.InitialRules))
				// Copy contents
				copy(configOut.MITM.Rules, configOut.MITM.InitialRules)
				logging.Printf("DEBUG", "watchFiles: read %d MITM rules from myproxy config file\n", len(configOut.MITM.Rules))
				configOut.MITM.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from MITM rules file %s\n", MITMFilePath)
			}
			for n, rule := range configOut.MITM.Rules {
				logging.Printf("DEBUG", "watchFiles: set MITM TLS config for rule %d \n", n+1)
				if rule.TLSConfig.ClientKey != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ClientKey\n")
				}
				if rule.TLSConfig.ClientCert != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ClientCert\n")
				}
				if rule.TLSConfig.ClientKeyfile != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ClientKeyfile\n")
				}
				if rule.TLSConfig.ClientCertfile != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ClientCertfile\n")
				}
				if rule.TLSConfig.ServerKey != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ServerKey\n")
				}
				if rule.TLSConfig.ServerCert != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ServerCert\n")
				}
				if rule.TLSConfig.ServerKeyfile != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ServerKeyfile\n")
				}
				if rule.TLSConfig.ServerCertfile != "" {
					logging.Printf("WARNING", "watchFiles: Invalid MITM TLS config ServerCertfile\n")
				}
				rule.TLSConf, err = setTLSConfig(&rule.TLSConfig, false)
				if err != nil {
					logging.Printf("ERROR", "watchFiles: could not set MITM TLS Config for rule %d, set to default: %v\n", n+1, err)
					rule.TLSConf = &tls.Config{MinVersion: tls.VersionTLS12}
				}
			}
		}

		if filepath.Clean(event.Name) == filepath.Clean(WebsocketFilePath) || filepath.Base(event.Name) == filepath.Base(WebsocketFilePath) {
			// Trigger reload on modification or replacement
			// Can happen multiple times in short time based on tol used to update file
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				file, err := openWithRetry(WebsocketFilePath, os.O_RDONLY, 0600)
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Could not read rules file %s: %v\n", WebsocketFilePath, err)
					continue
				}

				decoder := yaml.NewDecoder(file)
				decoder.KnownFields(true)
				var fileRules []WSRule
				err = decoder.Decode(&fileRules)
				_ = file.Close()
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Decoding file %s: %v\n", WebsocketFilePath, err)
					continue
				}
				configOut.Websocket.Mu.Lock()
				// Reset to Initial rules
				configOut.Websocket.Rules = make([]WSRule, len(configOut.Websocket.InitialRules))
				// Copy contents
				copy(configOut.Websocket.Rules, configOut.Websocket.InitialRules)
				logging.Printf("DEBUG", "watchFiles: read %d Websocket rules from myproxy config file\n", len(configOut.Websocket.Rules))
				// Append new rules
				configOut.Websocket.Rules = append(configOut.Websocket.Rules, fileRules...)
				logging.Printf("DEBUG", "watchFiles: addedd %d Websocket rules from Websocket Rules file\n", len(configOut.Websocket.Rules))
				configOut.Websocket.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from Websocket rules file %s\n", WebsocketFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.Websocket.Mu.Lock()
				// Reset to Initial rules
				configOut.Websocket.Rules = make([]WSRule, len(configOut.Websocket.InitialRules))
				// Copy contents
				copy(configOut.Websocket.Rules, configOut.Websocket.InitialRules)
				logging.Printf("DEBUG", "watchFiles: read %d Websocket rules from myproxy config file\n", len(configOut.Websocket.Rules))
				configOut.Websocket.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from Websocket rules file %s\n", WebsocketFilePath)
			}
		}
		if filepath.Clean(event.Name) == filepath.Clean(WiresharkFilePath) || filepath.Base(event.Name) == filepath.Base(WiresharkFilePath) {
			// Trigger reload on modification or replacement
			// Can happen multiple times in short time based on tol used to update file
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				file, err := openWithRetry(WiresharkFilePath, os.O_RDONLY, 0600)
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Could not read rules file %s: %v\n", WiresharkFilePath, err)
					continue
				}

				decoder := yaml.NewDecoder(file)
				decoder.KnownFields(true)
				var fileRules []WiresharkRule
				err = decoder.Decode(&fileRules)
				_ = file.Close()
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Decoding file %s: %v\n", WiresharkFilePath, err)
					continue
				}
				configOut.Wireshark.Mu.Lock()
				// Reset to Initial rules
				configOut.Wireshark.Rules = make([]WiresharkRule, len(configOut.Wireshark.InitialRules))
				// Copy contents
				copy(configOut.Wireshark.Rules, configOut.Wireshark.InitialRules)
				// Append new rules
				logging.Printf("DEBUG", "watchFiles: read %d Wireshark rules from myproxy config file\n", len(configOut.Wireshark.Rules))
				configOut.Wireshark.Rules = append(configOut.Wireshark.Rules, fileRules...)
				logging.Printf("DEBUG", "watchFiles: added %d Wireshark rules from Wireshark rules file\n", len(configOut.Wireshark.Rules))
				configOut.Wireshark.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from Wireshark rules file %s\n", WiresharkFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.Wireshark.Mu.Lock()
				// Reset to Initial rules
				configOut.Wireshark.Rules = make([]WiresharkRule, len(configOut.Wireshark.InitialRules))
				// Copy contents
				copy(configOut.Wireshark.Rules, configOut.Wireshark.InitialRules)
				logging.Printf("DEBUG", "watchFiles: read %d Wireshark rules from myproxy config file\n", len(configOut.Wireshark.Rules))
				configOut.Wireshark.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from Wireshark rules file %s\n", WiresharkFilePath)
			}
		}
	}
	logging.Printf("DEBUG", "watchFiles: Stop Event Loop\n")
}
