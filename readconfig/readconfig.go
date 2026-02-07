package readconfig

import (
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

var Config *Schema

// Used by interface to retrieve logging configuration
func (c *Schema) LogLevel() string   { return c.Logging.Level }
func (c *Schema) LogTrace() bool     { return c.Logging.Trace }
func (c *Schema) LogFile() string    { return c.Logging.File }
func (c *Schema) AccessFile() string { return c.Logging.AccessLog }
func (c *Schema) MilliSeconds() bool { return c.Logging.MilliSeconds }

// use `yaml:""` struct tag to parse fields name with
// kebabcase, snakecase, and camelcase fields
type PAC struct {
	Type      string `yaml:"type"`
	File      string `yaml:"file"`
	URL       string `yaml:"url"`
	Proxy     string `yaml:"proxy"`
	CacheTime int    `yaml:"cachetime"`
}
type Listen struct {
	IP           string `yaml:"ip"`
	Port         string `yaml:"port"`
	TLS          bool   `yaml:"tls"`
	Keyfile      string `yaml:"keyfile"`
	Certfile     string `yaml:"certfile"`
	CAfile       string `yaml:"rootcafile"`
	ReadTimeout  int    `yaml:"readtimeout"`
	WriteTimeout int    `yaml:"writetimeout"`
	IdleTimeout  int    `yaml:"idletimeout"`
}
type Logging struct {
	Level        string `yaml:"level"`
	File         string `yaml:"file"`
	AccessLog    string `yaml:"accesslog"`
	Trace        bool   `yaml:"trace"`
	MilliSeconds bool   `yaml:"msec"`
}
type Connection struct {
	ReadTimeout  int      `yaml:"readtimeout"`
	DNSTimeout   int      `yaml:"dnstimeout"`
	FallbackTime *int     `yaml:"fallbackdelay"`
	IPv4         *bool    `yaml:"ipv4"`
	IPv6         *bool    `yaml:"ipv6"`
	Timeout      int      `yaml:"timeout"`
	Keepalive    int      `yaml:"keepalive"`
	DNSServers   []string `yaml:"dnsservers"`
}
type WSRule struct {
	IP      string `yaml:"ip"`
	Client  string `yaml:"client"`
	Regex   string `yaml:"regex"`
	Timeout int    `yaml:"timeout"`
}
type WebSocket struct {
	Mu               sync.Mutex
	MaxPayloadLength int      `yaml:"maxplength"`
	Timeout          int      `yaml:"timeout"`
	Rules            []WSRule `yaml:"rules"`
	InitialRules     []WSRule
	RulesFile        string `yaml:"rulesfile"`
}
type FTP struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
type MitmRule struct {
	IP       string `yaml:"ip"`
	Client   string `yaml:"client"`
	Regex    string `yaml:"regex"`
	CertFile string `yaml:"certfile"`
}
type MITM struct {
	Mu           sync.Mutex
	Enable       bool       `yaml:"enable"`
	Key          string     `yaml:"key"`
	Cert         string     `yaml:"cert"`
	Keyfile      string     `yaml:"keyfile"`
	Certfile     string     `yaml:"certfile"`
	Rules        []MitmRule `yaml:"rules"`
	InitialRules []MitmRule
	RulesFile    string `yaml:"rulesfile"`
}
type WiresharkRule struct {
	IP string `yaml:"ip"`
}
type Wireshark struct {
	Mu                sync.Mutex
	Enable            bool            `yaml:"enable"`
	UnmaskedWebSocket bool            `yaml:"unmaskedwebsocket"`
	IP                string          `yaml:"ip"`
	Port              string          `yaml:"port"`
	Rules             []WiresharkRule `yaml:"rules"`
	InitialRules      []WiresharkRule
	RulesFile         string `yaml:"rulesfile"`
}
type Clamd struct {
	Enable       bool   `yaml:"enable"`
	Block        bool   `yaml:"block"`
	BlockOnError bool   `yaml:"blockonerror"`
	Certfile     string `yaml:"certfile"`
	Keyfile      string `yaml:"keyfile"`
	CAfile       string `yaml:"rootcafile"`
	Connection   string `yaml:"connection"`
}
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
type Schema struct {
	PAC        PAC        `yaml:"pac"`
	Proxy      Proxy      `yaml:"proxy"`
	Listen     Listen     `yaml:"listen"`
	Logging    Logging    `yaml:"logging"`
	Connection Connection `yaml:"connection"`
	WebSocket  WebSocket  ` yaml:"websocket"`
	FTP        FTP        `yaml:"ftp"`
	MITM       MITM       `yaml:"mitm"`
	Wireshark  Wireshark  `yaml:"wireshark"`
	Clamd      Clamd      `yaml:"clamd"`
}

var msec bool

func printf(level string, format string, a ...any) (int, error) {
	message := fmt.Sprintf(format, a...)
	formatString := time.RFC1123
	if msec {
		formatString = "Mon, 02 Jan 2006 15:04:05.000 MST"
	}
	timeStamp := time.Now().Format(formatString)
	return fmt.Printf("%s %s: %s", timeStamp, level, message)
}

func ReadConfig(configFilename string, watcher *fsnotify.Watcher) (*Schema, error) {

	osType := runtime.GOOS

	filePath, err := filepath.Abs(configFilename)
	if err != nil {
		printf("ERROR", "Readconfig: Getting file %s, %v\n", configFilename, err)
		return nil, err
	}

	file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
	if err != nil {
		printf("ERROR", "Readconfig: opening file %s, %v\n", filePath, err)
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var configOut = Schema{}
	err = decoder.Decode(&configOut)

	msec = configOut.Logging.MilliSeconds

	if err != nil {
		printf("ERROR", "ReadConfig: decoding file %s: %v\n", filePath, err)
		return nil, err
	}
	if configOut.Logging.File == "" {
		configOut.Logging.File = "stdout"
	} else if strings.ToUpper(configOut.Logging.File) == "SYSLOG" || strings.ToUpper(configOut.Logging.File) == "EVENTLOG" {
		configOut.Logging.File = strings.ToUpper(configOut.Logging.File)
	} else if strings.ToUpper(configOut.Logging.File) != "STDOUT" {
		var logFile *os.File
		logFilepath, err := filepath.Abs(configOut.Logging.File)
		if err != nil {
			printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Logging.File, err)
			return nil, err
		}
		configOut.Logging.File = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.File)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR, 0600)
				if err != nil {
					printf("ERROR", "ReadConfig: logfile %s not writeable\n", configOut.Logging.File)
					return nil, err
				} else {
					printf("WARNING", "ReadConfig: logfile %s exists. Will append \n", configOut.Logging.File)
				}
				defer logFile.Close()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				printf("ERROR", "ReadConfig: logfile %s cannot be created\n", configOut.Logging.File)
				return nil, err
			} else {
				printf("INFO", "ReadConfig: logfile %s created.\n", configOut.Logging.File)
			}
			defer logFile.Close()
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
			printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Logging.AccessLog, err)
			return nil, err
		}
		configOut.Logging.AccessLog = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.AccessLog)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR, 0600)
				if err != nil {
					printf("ERROR", "ReadConfig: access logfile %s not writeable\n", configOut.Logging.AccessLog)
					return nil, err
				} else {
					printf("WARNING", "ReadConfig: access logfile %s exists. Will append \n", configOut.Logging.AccessLog)
				}
				defer logFile.Close()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				printf("ERROR", "ReadConfig: access logfile %s cannot be created\n", configOut.Logging.AccessLog)
				return nil, err
			} else {
				printf("INFO", "ReadConfig: access logfile %s created.\n", configOut.Logging.AccessLog)
			}
			defer logFile.Close()
		}
	}

	printf("INFO", "ReadConfig: Read log config.\n")
	printf("INFO", "ReadConfig: Start log processor.\n")
	// After logging config check start log processor
	go logging.LogProcessor(&configOut)
	// Give Processor goroutine some time for setup
	time.Sleep(2 * time.Second)
	printf("INFO", "ReadConfig: log processor started.\n")

	if configOut.PAC.Type != "FILE" && configOut.PAC.Type != "URL" && configOut.PAC.Type != "" {
		logging.Printf("ERROR", "ReadConfig: Reading PAC type field: %s\n", configOut.PAC.Type)
		logging.Printf("ERROR", "ReadConfig: Only FILE and URL supported\n")
		return nil, errors.New("Wrong PAC type")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File == "" {
		logging.Printf("ERROR", "ReadConfig: Reading PAC type FILE: %s\n", configOut.PAC.File)
		logging.Printf("ERROR", "ReadConfig: FILE needs a filename\n")
		return nil, errors.New("PAC File name missing")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File != "" {
		pacFilepath, err := filepath.Abs(configOut.PAC.File)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.PAC.File, err)
			return nil, err
		}
		configOut.PAC.File = pacFilepath
		_, err = os.Stat(configOut.PAC.File)
		if errors.Is(err, os.ErrNotExist) || err != nil {
			logging.Printf("ERROR", "ReadConfig: Can not read PAC file %s\n", configOut.PAC.File)
			return nil, err
		}
	}

	if configOut.PAC.Type == "URL" && configOut.PAC.URL == "" {
		logging.Printf("ERROR", "ReadConfig: Reading PAC type URL: %s\n", configOut.PAC.URL)
		logging.Printf("ERROR", "ReadConfig: URL needs a url\n")
		return nil, errors.New("PAC URL missing")
	}
	for i, v := range configOut.Proxy.Authentication {
		if v != "ntlm" && v != "negotiate" && v != "basic" {
			logging.Printf("ERROR", "ReadConfig: Reading authentication field: %d:%s\n", i+1, v)
			logging.Printf("ERROR", "ReadConfig: Only ntln,negotiate and basic are supported\n")
			return nil, errors.New("Invalid Authentication type")
		}
	}
	if osType != "windows" {
		if configOut.Proxy.NtlmUser != "" && configOut.Proxy.NtlmPass == "" {
			fmt.Printf("Enter NTLM Password for %s: ", configOut.Proxy.NtlmUser)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: NTLM Password read error\n")
				return nil, err
			}
			fmt.Printf("\n")
			configOut.Proxy.NtlmPass = string(bytePassword)
		}

		if configOut.Proxy.KerberosConfig != "" {
			kconfigFilepath, err := filepath.Abs(configOut.Proxy.KerberosConfig)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Proxy.KerberosConfig, err)
				return nil, err
			}
			configOut.Proxy.KerberosConfig = kconfigFilepath
			_, err = os.Stat(configOut.Proxy.KerberosConfig)
			if errors.Is(err, os.ErrNotExist) || err != nil {
				logging.Printf("ERROR", "ReadConfig: Can not read Kerberos config file %s\n", configOut.Proxy.KerberosConfig)
				return nil, err
			}
		}

		if configOut.Proxy.KerberosUser != "" && configOut.Proxy.KerberosPass == "" && configOut.Proxy.KerberosCache == "" {
			fmt.Printf("Enter Kerberos Password for %s: ", configOut.Proxy.KerberosUser)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Kerberos Password read error\n")
				return nil, err
			}
			fmt.Printf("\n")
			configOut.Proxy.KerberosPass = string(bytePassword)
		}
		if configOut.Proxy.KerberosCache != "" {
			ccacheFilepath, err := filepath.Abs(configOut.Proxy.KerberosCache)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Proxy.KerberosCache, err)
				return nil, err
			}
			configOut.Proxy.KerberosCache = ccacheFilepath
		}
	} else {
		logging.Printf("INFO", "ReadConfig: NTLM and Kerberos details are not used with SSPI\n")
	}

	if configOut.Proxy.BasicUser != "" && configOut.Proxy.BasicPass == "" {
		fmt.Printf("Enter Basic Password for %s: ", configOut.Proxy.BasicUser)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Basic  Password read error\n")
			return nil, err
		}
		fmt.Printf("\n")
		configOut.Proxy.BasicPass = string(bytePassword)
	}
	if configOut.Listen.TLS && (configOut.Listen.Keyfile == "" || configOut.Listen.Certfile == "") {
		logging.Printf("ERROR", "ReadConfig: TLS requires Certfile and Keyfile file: %s/%s\n", configOut.Listen.Certfile, configOut.Listen.Keyfile)
		return nil, err
	}
	if configOut.Listen.Keyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.Listen.Keyfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Listen.Keyfile, err)
			return nil, err
		}
		configOut.Listen.Keyfile = keyFilepath
	}
	if configOut.Listen.Certfile != "" {
		certFilepath, err := filepath.Abs(configOut.Listen.Certfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Listen.Certfile, err)
			return nil, err
		}
		configOut.Listen.Certfile = certFilepath
	}
	if configOut.MITM.Keyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.MITM.Keyfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.MITM.Keyfile, err)
			return nil, err
		}
		configOut.MITM.Keyfile = keyFilepath
	}
	if configOut.MITM.Certfile != "" {
		certFilepath, err := filepath.Abs(configOut.MITM.Certfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.MITM.Certfile, err)
			return nil, err
		}
		configOut.MITM.Certfile = certFilepath
	}
	if configOut.Listen.CAfile != "" && configOut.Listen.CAfile != "insecure" {
		caFilepath, err := filepath.Abs(configOut.Listen.CAfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Listen.CAfile, err)
			return nil, err
		}
		_, err = os.Stat(caFilepath)
		if err != nil {
			return nil, err
		}
		configOut.Listen.CAfile = caFilepath
	}
	if configOut.MITM.Enable {
		// Check all combinations
		switch {
		case
			configOut.MITM.Key != "" && configOut.MITM.Cert == "",
			configOut.MITM.Key == "" && configOut.MITM.Cert != "",
			configOut.MITM.Keyfile != "" && configOut.MITM.Certfile == "",
			configOut.MITM.Keyfile == "" && configOut.MITM.Certfile != "",
			configOut.MITM.Key != "" && configOut.MITM.Keyfile != "",
			configOut.MITM.Cert != "" && configOut.MITM.Certfile != "":
			return nil, errors.New("Invalid MITM certificate configuration")
		default:
		}
		if configOut.MITM.Keyfile != "" {
			buf, err := os.ReadFile(configOut.MITM.Keyfile)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Could not read Keyfile file: %v\n", err)
				return nil, err
			}
			configOut.MITM.Key = string(buf)
			buf, err = os.ReadFile(configOut.MITM.Certfile)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Could not read Keyfile file: %v\n", err)
				return nil, err
			}
			configOut.MITM.Cert = string(buf)
		}
		if configOut.MITM.RulesFile != "" {
			filePath, err := filepath.Abs(configOut.MITM.RulesFile)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.MITM.RulesFile, err)
				return nil, err
			}
			file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Could not read rules file %s: %v\n", filePath, err)
				return nil, err
			}
			defer file.Close()

			decoder := yaml.NewDecoder(file)
			decoder.KnownFields(true)
			var fileRules []MitmRule
			err = decoder.Decode(&fileRules)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Decoding file %s: %v\n", filePath, err)
				return nil, err
			}

			// Save initial rules
			configOut.MITM.InitialRules = make([]MitmRule, len(configOut.MITM.Rules))
			// Copy contents
			copy(configOut.MITM.InitialRules, configOut.MITM.Rules)

			configOut.MITM.Rules = append(configOut.MITM.Rules, fileRules...)
			// Watch config file
			fileDir := filepath.Dir(filePath)
			//err = watcher.Add(filePath)
			//if err != nil {
			//	logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", filePath, err)
			//	return nil, err
			//}
			err = watcher.Add(fileDir)
			if err != nil {
				logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", fileDir, err)
				return nil, err
			}
			logging.Printf("INFO", "ReadConfig: Watching file %s\n", filePath)
		}

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
	if configOut.Wireshark.IP == "" {
		configOut.Wireshark.IP = "127.0.0.1"
	}
	if configOut.Wireshark.RulesFile != "" {
		filePath, err := filepath.Abs(configOut.Wireshark.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Wireshark.RulesFile, err)
			return nil, err
		}
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Could not read wireshark rules file %s: %v\n", configOut.Wireshark.RulesFile, err)
			return nil, err
		}
		defer file.Close()

		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		var fileRules []WiresharkRule
		err = decoder.Decode(&fileRules)

		// Save initial rules
		configOut.Wireshark.InitialRules = make([]WiresharkRule, len(configOut.Wireshark.Rules))
		// Copy contents
		copy(configOut.Wireshark.InitialRules, configOut.Wireshark.Rules)

		configOut.Wireshark.Rules = append(configOut.Wireshark.Rules, fileRules...)

		// Watch config file
		fileDir := filepath.Dir(filePath)
		//err = watcher.Add(filePath)
		//if err != nil {
		//	logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", filePath, err)
		//	return nil, err
		//}
		err = watcher.Add(fileDir)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", fileDir, err)
			return nil, err
		}
		logging.Printf("INFO", "ReadConfig: Watching file %s\n", filePath)
	}

	if configOut.Wireshark.Port == "" {
		configOut.Wireshark.Port = "19000"
	}
	if configOut.Logging.Level == "" {
		configOut.Logging.Level = "info"
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
		return nil, errors.New("Require IPv6 or IPv4")
	}
	if len(configOut.Connection.DNSServers) > 0 {
		for i := 0; i < len(configOut.Connection.DNSServers); i++ {
			_, _, err := net.SplitHostPort(configOut.Connection.DNSServers[i])
			if err != nil {
				configOut.Connection.DNSServers[i] = configOut.Connection.DNSServers[i] + ":53"
			}
		}
	}
	if configOut.Connection.Timeout == 0 {
		configOut.Connection.Timeout = 5
	}
	if configOut.Connection.Keepalive == 0 {
		configOut.Connection.Keepalive = 10
	}
	if configOut.WebSocket.Timeout == 0 {
		if configOut.Connection.ReadTimeout != 0 {
			configOut.WebSocket.Timeout = configOut.Connection.ReadTimeout
		}
	}
	if configOut.WebSocket.MaxPayloadLength == 0 {
		configOut.WebSocket.MaxPayloadLength = 16 * 65535
	}
	if configOut.WebSocket.RulesFile != "" {
		filePath, err := filepath.Abs(configOut.WebSocket.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.WebSocket.RulesFile, err)
			return nil, err
		}
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Could not read rules file %s: %v\n", filePath, err)
			return nil, err
		}
		defer file.Close()

		decoder := yaml.NewDecoder(file)
		decoder.KnownFields(true)
		var fileRules []WSRule
		err = decoder.Decode(&fileRules)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Decoding file %s: %v\n", filePath, err)
			return nil, err
		}

		// Save initial rules
		configOut.WebSocket.InitialRules = make([]WSRule, len(configOut.WebSocket.Rules))
		// Copy contents
		copy(configOut.WebSocket.InitialRules, configOut.WebSocket.Rules)

		configOut.WebSocket.Rules = append(configOut.WebSocket.Rules, fileRules...)
		// Watch config file
		fileDir := filepath.Dir(filePath)
		//err = watcher.Add(filePath)
		//if err != nil {
		//	logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", filePath, err)
		//	return nil, err
		//}
		err = watcher.Add(fileDir)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Watching file %s: %v\n", fileDir, err)
			return nil, err
		}
		logging.Printf("INFO", "ReadConfig: Watching file %s\n", filePath)
	}
	if configOut.Clamd.Connection == "" {
		configOut.Clamd.Connection = "unix:/var/run/clamav/clamd.ctl"
	}
	prefix := "tls:"
	if strings.HasPrefix(configOut.Clamd.Connection, prefix) {
		if configOut.Clamd.Certfile == "" || configOut.Clamd.Keyfile == "" {
			return nil, errors.New("Missing Client Cert or Key to authenticate")
		}
	}

	if configOut.Clamd.Certfile != "" {
		certFilepath, err := filepath.Abs(configOut.Clamd.Certfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Clamd.Certfile, err)
			return nil, err
		}
		_, err = os.Stat(certFilepath)
		if err != nil {
			return nil, err
		}
		configOut.Clamd.Certfile = certFilepath
	}
	if configOut.Clamd.Keyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.Clamd.Keyfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Clamd.Keyfile, err)
			return nil, err
		}
		_, err = os.Stat(keyFilepath)
		if err != nil {
			return nil, err
		}
		configOut.Clamd.Keyfile = keyFilepath
	}
	if configOut.Clamd.CAfile != "" && configOut.Clamd.CAfile != "insecure" {
		caFilepath, err := filepath.Abs(configOut.Clamd.CAfile)
		if err != nil {
			logging.Printf("ERROR", "ReadConfig: Getting file %s: %v\n", configOut.Clamd.CAfile, err)
			return nil, err
		}
		_, err = os.Stat(caFilepath)
		if err != nil {
			return nil, err
		}
		configOut.Clamd.CAfile = caFilepath
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
	var maxRetries int = 10
	var delay time.Duration = 1 * time.Second
	const ERROR_SHARING_VIOLATION syscall.Errno = 32 // Windows error code

	for i := 1; i <= maxRetries; i++ {
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
	var MITMFilePath string = ""
	var WebSocketFilePath string = ""
	var WiresharkFilePath string = ""
	var err error

	logLevel := strings.ToUpper(configOut.Logging.Level)

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
	if configOut.WebSocket.RulesFile != "" {
		WebSocketFilePath, err = filepath.Abs(configOut.WebSocket.RulesFile)
		if err != nil {
			logging.Printf("ERROR", "watchFiles: Getting file %s: %v\n", configOut.WebSocket.RulesFile, err)
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
				file.Close()
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Decoding file %s: %v\n", MITMFilePath, err)
					continue
				}
				configOut.MITM.Mu.Lock()
				// Reset to Initial rules
				configOut.MITM.Rules = make([]MitmRule, len(configOut.MITM.InitialRules))
				// Copy contents
				copy(configOut.MITM.Rules, configOut.MITM.InitialRules)
				// Append new rules
				configOut.MITM.Rules = append(configOut.MITM.Rules, fileRules...)
				configOut.MITM.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from MITM Rules file %s\n", MITMFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.MITM.Mu.Lock()
				// Reset to Initial rules
				configOut.MITM.Rules = make([]MitmRule, len(configOut.MITM.InitialRules))
				// Copy contents
				copy(configOut.MITM.Rules, configOut.MITM.InitialRules)
				configOut.MITM.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from MITM Rules file %s\n", MITMFilePath)
			}

		}
		if filepath.Clean(event.Name) == filepath.Clean(WebSocketFilePath) || filepath.Base(event.Name) == filepath.Base(WebSocketFilePath) {
			// Trigger reload on modification or replacement
			// Can happen multiple times in short time based on tol used to update file
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				file, err := openWithRetry(WebSocketFilePath, os.O_RDONLY, 0600)
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Could not read rules file %s: %v\n", WebSocketFilePath, err)
					continue
				}

				decoder := yaml.NewDecoder(file)
				decoder.KnownFields(true)
				var fileRules []WSRule
				err = decoder.Decode(&fileRules)
				file.Close()
				if err != nil {
					logging.Printf("ERROR", "watchFiles: Decoding file %s: %v\n", WebSocketFilePath, err)
					continue
				}
				configOut.WebSocket.Mu.Lock()
				// Reset to Initial rules
				configOut.WebSocket.Rules = make([]WSRule, len(configOut.WebSocket.InitialRules))
				// Copy contents
				copy(configOut.WebSocket.Rules, configOut.WebSocket.InitialRules)
				// Append new rules
				configOut.WebSocket.Rules = append(configOut.WebSocket.Rules, fileRules...)
				configOut.WebSocket.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from WebSocket Rules file %s\n", WebSocketFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.WebSocket.Mu.Lock()
				// Reset to Initial rules
				configOut.WebSocket.Rules = make([]WSRule, len(configOut.WebSocket.InitialRules))
				// Copy contents
				copy(configOut.WebSocket.Rules, configOut.WebSocket.InitialRules)
				configOut.WebSocket.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from WebSocket Rules file %s\n", WebSocketFilePath)
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
				file.Close()
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
				configOut.Wireshark.Rules = append(configOut.Wireshark.Rules, fileRules...)
				configOut.Wireshark.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Reloaded rules from Wireshark Rules file %s\n", WiresharkFilePath)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				logging.Printf("DEBUG", "watchFiles: Event %s on file %s\n", event.Op, event.Name)
				configOut.Wireshark.Mu.Lock()
				// Reset to Initial rules
				configOut.Wireshark.Rules = make([]WiresharkRule, len(configOut.Wireshark.InitialRules))
				// Copy contents
				copy(configOut.Wireshark.Rules, configOut.Wireshark.InitialRules)
				configOut.Wireshark.Mu.Unlock()
				logging.Printf("INFO", "watchFiles: Deleted rules from Wireshark Rules file %s\n", WiresharkFilePath)
			}
		}
	}
	if logLevel == "DEBUG" {
		logging.Printf("DEBUG", "watchFiles: Stop Event Loop\n")
	}
}
