package readconfig

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

var Config *Schema

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
	IP   string `yaml:"ip"`
	Port string `yaml:"port"`
}
type Logging struct {
	Level     string `yaml:"level"`
	File      string `yaml:"file"`
	AccessLog string `yaml:"accesslog"`
	Trace     bool   `yaml:"trace"`
}
type Connection struct {
	Timeout   int `yaml:"timeout"`
	Keepalive int `yaml:"keepalive"`
}
type WebSocket struct {
	Timeout int      `yaml:"timeout"`
	IncExc  []string `yaml:"incexc"`
}
type FTP struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
type MITM struct {
	Enable     bool     `yaml:"enable"`
	Key        string   `yaml:"key"`
	Cert       string   `yaml:"cert"`
	Keyfile    string   `yaml:"keyfile"`
	Certfile   string   `yaml:"certfile"`
	IncExc     []string `yaml:"incexc"`
	IncExcFile string   `yaml:"incexcfile"`
}
type Wireshark struct {
	IP     string   `yaml:"ip"`
	Port   string   `yaml:"port"`
	IncExc []string `yaml:"incexc"`
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
}

func ReadConfig(configFilename string) (*Schema, error) {

	osType := runtime.GOOS

	filePath, err := filepath.Abs(configFilename)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)

	if err != nil {
		log.Printf("ERROR: Readconfig: %v\n", err)
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var configOut = Schema{}
	err = decoder.Decode(&configOut)

	if err != nil {
		log.Printf("ERROR: ReadConfig: decoding file: %v\n", err)
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
			return nil, err
		}
		configOut.Logging.File = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.File)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR, 0600)
				if err != nil {
					log.Printf("ERROR: ReadConfig: logfile %s not writeable\n", configOut.Logging.File)
					return nil, err
				} else {
					log.Printf("WARNING: ReadConfig: logfile %s exists. Will append \n", configOut.Logging.File)
				}
				defer logFile.Close()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.File, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				log.Printf("ERROR: ReadConfig: logfile %s cannot be created\n", configOut.Logging.File)
				return nil, err
			} else {
				log.Printf("INFO: ReadConfig: logfile %s created.\n", configOut.Logging.File)
			}
			defer logFile.Close()
		}
	}
	if configOut.Logging.AccessLog == "" {
		configOut.Logging.AccessLog = "stdout"
	} else if strings.ToUpper(configOut.Logging.AccessLog) == "SYSLOG" || strings.ToUpper(configOut.Logging.AccessLog) == "EVENTLOG" {
		configOut.Logging.File = strings.ToUpper(configOut.Logging.AccessLog)
	} else if strings.ToUpper(configOut.Logging.AccessLog) != "STDOUT" {
		var logFile *os.File
		logFilepath, err := filepath.Abs(configOut.Logging.AccessLog)
		if err != nil {
			return nil, err
		}
		configOut.Logging.AccessLog = logFilepath
		fileInfo, err := os.Stat(configOut.Logging.AccessLog)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			fileMode := fileInfo.Mode()
			if fileMode.IsRegular() {
				logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR, 0600)
				if err != nil {
					log.Printf("ERROR: ReadConfig: access logfile %s not writeable\n", configOut.Logging.AccessLog)
					return nil, err
				} else {
					log.Printf("WARNING: ReadConfig: access logfile %s exists. Will append \n", configOut.Logging.AccessLog)
				}
				defer logFile.Close()
			}
		} else {
			logFile, err = os.OpenFile(configOut.Logging.AccessLog, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				log.Printf("ERROR: ReadConfig: access logfile %s cannot be created\n", configOut.Logging.AccessLog)
				return nil, err
			} else {
				log.Printf("INFO: ReadConfig: access logfile %s created.\n", configOut.Logging.AccessLog)
			}
			defer logFile.Close()
		}
	}

	if configOut.PAC.Type != "FILE" && configOut.PAC.Type != "URL" && configOut.PAC.Type != "" {
		log.Printf("ERROR: ReadConfig: reading PAC type field: %s\n", configOut.PAC.Type)
		log.Printf("ERROR: ReadConfig: only FILE and URL supported\n")
		return nil, errors.New("Wrong PAC type")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File == "" {
		log.Printf("ERROR: ReadConfig: reading PAC type FILE: %s\n", configOut.PAC.File)
		log.Printf("ERROR: ReadConfig: FILE needs a filename\n")
		return nil, errors.New("PAC File name missing")
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File != "" {
		pacFilepath, err := filepath.Abs(configOut.PAC.File)
		if err != nil {
			return nil, err
		}
		configOut.PAC.File = pacFilepath
		_, err = os.Stat(configOut.PAC.File)
		if errors.Is(err, os.ErrNotExist) || err != nil {
			log.Printf("ERROR: ReadConfig: Can not read PAC file %s\n", configOut.PAC.File)
			return nil, err
		}
	}

	if configOut.PAC.Type == "URL" && configOut.PAC.URL == "" {
		log.Printf("ERROR: ReadConfig: reading PAC type URL: %s\n", configOut.PAC.URL)
		log.Printf("ERROR: ReadConfig: URL needs a url\n")
		return nil, errors.New("PAC URL missing")
	}
	for i, v := range configOut.Proxy.Authentication {
		if v != "ntlm" && v != "negotiate" && v != "basic" {
			log.Printf("ERROR: ReadConfig: reading authentication field: %d:%s\n", i+1, v)
			log.Printf("ERROR: ReadConfig: only ntln,negotiate and basic are supported\n")
			return nil, errors.New("Invalid Authentication type")
		}
	}
	if osType != "windows" {
		if configOut.Proxy.NtlmUser != "" && configOut.Proxy.NtlmPass == "" {
			fmt.Printf("Enter NTLM Password for %s: ", configOut.Proxy.NtlmUser)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Printf("ERROR: ReadConfig: NTLM Password read error\n")
				fmt.Printf("ReadConfig: NTLM Password read error\n")
				return nil, err
			}
			fmt.Printf("\n")
			configOut.Proxy.NtlmPass = string(bytePassword)
		}

		if configOut.Proxy.KerberosConfig != "" {
			kconfigFilepath, err := filepath.Abs(configOut.Proxy.KerberosConfig)
			if err != nil {
				return nil, err
			}
			configOut.Proxy.KerberosConfig = kconfigFilepath
			_, err = os.Stat(configOut.Proxy.KerberosConfig)
			if errors.Is(err, os.ErrNotExist) || err != nil {
				log.Printf("ERROR: ReadConfig: Can not read Kerberos config file %s\n", configOut.Proxy.KerberosConfig)
				return nil, err
			}
		}

		if configOut.Proxy.KerberosUser != "" && configOut.Proxy.KerberosPass == "" && configOut.Proxy.KerberosCache == "" {
			fmt.Printf("Enter Kerberos Password for %s: ", configOut.Proxy.KerberosUser)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Printf("ERROR: ReadConfig: Kerberos Password read error\n")
				fmt.Printf("ReadConfig: Kerberos Password read error\n")
				return nil, err
			}
			fmt.Printf("\n")
			configOut.Proxy.KerberosPass = string(bytePassword)
		}
		if configOut.Proxy.KerberosCache != "" {
			ccacheFilepath, err := filepath.Abs(configOut.Proxy.KerberosCache)
			if err != nil {
				return nil, err
			}
			configOut.Proxy.KerberosCache = ccacheFilepath
		}
	} else {
		log.Printf("INFO: ReadConfig: NTLM and Kerberos details are not used with SSPI\n")
	}

	if configOut.Proxy.BasicUser != "" && configOut.Proxy.BasicPass == "" {
		fmt.Printf("Enter Basic Password for %s: ", configOut.Proxy.BasicUser)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Printf("ERROR: ReadConfig: Basic  Password read error\n")
			fmt.Printf("ReadConfig: Basic  Password read error\n")
			return nil, err
		}
		fmt.Printf("\n")
		configOut.Proxy.BasicPass = string(bytePassword)
	}
	if configOut.MITM.Keyfile != "" {
		keyFilepath, err := filepath.Abs(configOut.MITM.Keyfile)
		if err != nil {
			return nil, err
		}
		configOut.MITM.Keyfile = keyFilepath
	}
	if configOut.MITM.Certfile != "" {
		certFilepath, err := filepath.Abs(configOut.MITM.Certfile)
		if err != nil {
			return nil, err
		}
		configOut.MITM.Certfile = certFilepath
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
				log.Printf("ERROR: ReadConfig: could not read Keyfile file: %v\n", err)
				return nil, err
			}
			configOut.MITM.Key = string(buf)
			buf, err = os.ReadFile(configOut.MITM.Certfile)
			if err != nil {
				log.Printf("ERROR: ReadConfig: could not read Keyfile file: %v\n", err)
				return nil, err
			}
			configOut.MITM.Cert = string(buf)
		}
		if configOut.MITM.IncExcFile != "" {
			buf, err := os.ReadFile(configOut.MITM.IncExcFile)
			if err != nil {
				log.Printf("ERROR: ReadConfig: could not read Include/Exclude file: %v\n", err)
				return nil, err
			}
			bufStr := strings.Split(string(buf), "\n")
			configOut.MITM.IncExc = append(configOut.MITM.IncExc, bufStr...)
		}

	}
	for i, v := range configOut.MITM.IncExc {
		// IncExc string format (!|)src,(client|proxy);regex
		isEmpty, _ := regexp.MatchString("^[ ]*$", v)
		hasThreeEntries, _ := regexp.MatchString("^(!|)\\d+\\.\\d+\\.\\d+\\.\\d+(|/\\d+);(client|proxy)*;.*", v)
		hasFourEntries, _ := regexp.MatchString("^(!|)\\d+\\.\\d+\\.\\d+\\.\\d+(|/\\d+);(client|proxy)*;[^;]*;.*", v)
		if isEmpty {
			continue
		}
		if !hasThreeEntries {
			log.Printf("ERROR: ReadConfig: wrong syntax of MITM Include/Exclude field: %d:%s\n", i+1, v)
			return nil, errors.New("Invalid Include/Exclude line")
		}
		spos := strings.Index(v, ";")
		cidr := v[:spos]
		epos := strings.Index(cidr, "!")
		cpos := strings.Index(cidr, "/")
		// log.Printf("DEBUG: ReadConfig: Include/Exclude %s, Exclamation: %d, Semicolon: %d\n",v,epos,spos)
		if epos == 0 {
			cidr = cidr[1:]
		}
		if cpos == -1 {
			cidr = cidr + "/32"
		}
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("ERROR: ReadConfig: wrong syntax of MITM Include/Exclude field: %d:%s err:%v\n", i+1, v, err)
			return nil, errors.New("Invalid Include/Exclude line")
		}
		if hasFourEntries {
			// Parse Include/Exclude line
			rpos := strings.LastIndex(v, ";")
			rootCAStr := v[rpos+1:]
			rootCAFilepath, err := filepath.Abs(rootCAStr)
			if err != nil {
				return nil, err
			}
			_, err = os.Stat(rootCAFilepath)
			if errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	if configOut.Listen.IP == "" {
		configOut.Listen.IP = "127.0.0.1"
	}
	if configOut.Listen.Port == "" {
		configOut.Listen.Port = "9080"
	}
	if configOut.Wireshark.Port == "" {
		configOut.Wireshark.Port = "19000"
	}
	if configOut.Logging.Level == "" {
		configOut.Logging.Level = "info"
	}
	if configOut.Connection.Timeout == 0 {
		configOut.Connection.Timeout = 5
	}
	if configOut.Connection.Keepalive == 0 {
		configOut.Connection.Keepalive = 10
	}
	if configOut.WebSocket.Timeout == 0 {
		configOut.WebSocket.Timeout = 30
	}
	if configOut.FTP.Username == "" {
		configOut.FTP.Username = "anonymous"
	}
	if configOut.FTP.Password == "" {
		configOut.FTP.Password = "anonymous@myproxy"
	}
	return &configOut, nil
}
