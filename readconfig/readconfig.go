package readconfig

import (
        "syscall"
        "golang.org/x/term"
	"gopkg.in/yaml.v3"
	"fmt"
	"log"
	"errors"
	"os"
	"runtime"
)

var Config *Schema

// use `yaml:""` struct tag to parse fields name with
// kebabcase, snakecase, and camelcase fields
type PAC struct {
	Type  string `yaml:"type"`
	File  string `yaml:"file"`
	URL   string `yaml:"url"`
	Proxy string `yaml:"proxy"`
}
type Listen struct {
	IP    string `yaml:"ip"`
	Port  string `yaml:"port"`
}
type Logging struct {
	Level string `yaml:"level"`
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
	LocalBasicUser   string   `yaml:"LocalBasicUser"`
	LocalBasicHash   string   `yaml:"LocalBasicHash"`
}
type Schema struct {
	PAC   PAC   `yaml:"pac"`
	Proxy Proxy `yaml:"proxy"`
	Listen Listen `yaml:"listen"`
	Logging Logging `yaml:"logging"`
}

func ReadConfig(configFilename string) (*Schema, error) {

	osType := runtime.GOOS

	file, err := os.OpenFile(configFilename, os.O_RDONLY, 0600)

	if err != nil {
		log.Printf("ERROR: Readconfig: %v\n",err)
		return nil, err
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var configOut = Schema{}
	err = decoder.Decode(&configOut)

	if err != nil {
		log.Printf("ERROR: ReadConfig: decoding file: %v\n",err)
		return nil, err
	}
	if configOut.PAC.Type != "FILE" && configOut.PAC.Type != "URL" {
		log.Printf("ERROR: ReadConfig: reading type field: %s\n", configOut.PAC.Type)
		log.Printf("ERROR: ReadConfig: only FILE and URL supported\n")
		return nil, err
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File == "" {
		log.Printf("ERROR: ReadConfig: reading type file: %s\n", configOut.PAC.File)
		log.Printf("ERROR: ReadConfig: FILE needs a filename\n")
		return nil, err
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File != "" {
		_, err := os.Stat(configOut.PAC.File)
		if errors.Is(err, os.ErrNotExist) ||  err != nil {
			log.Printf("ERROR: ReadConfig: Can not read pac file %s\n",configOut.PAC.File)
			return nil, err
		}
	}

	if configOut.PAC.Type == "URL" && configOut.PAC.URL == "" {
		log.Printf("ERROR: ReadConfig: reading type url: %s\n", configOut.PAC.URL)
		log.Printf("ERROR: ReadConfig: URL needs a url\n")
		return nil, err
	}
	for i, v := range configOut.Proxy.Authentication {
		if v != "ntlm" && v != "negotiate" && v != "basic" {
			log.Printf("ERROR: ReadConfig: reading authentication field: %d:%s\n", i+1, v)
			log.Printf("ERROR: ReadConfig: only ntln,negotiate and basic supported\n")
			return nil, err
		}
	}
	if osType != "windows" {
		if configOut.Proxy.NtlmUser != "" && configOut.Proxy.NtlmPass == "" {
			fmt.Printf("Enter NTLM Password for %s: ",configOut.Proxy.NtlmUser)
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
			_, err := os.Stat(configOut.Proxy.KerberosConfig)
			if errors.Is(err, os.ErrNotExist) ||  err != nil {
				log.Printf("ERROR: ReadConfig: Can not read Kerberos config file %s\n",configOut.Proxy.KerberosConfig)
				return nil, err
			}
		}

        	if configOut.Proxy.KerberosUser != "" && configOut.Proxy.KerberosPass == "" && configOut.Proxy.KerberosCache == "" {
        		fmt.Printf("Enter Kerberos Password for %s: ",configOut.Proxy.KerberosUser)
                	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
                	if err != nil {
				log.Printf("ERROR: ReadConfig: Kerberos Password read error\n")
				fmt.Printf("ReadConfig: Kerberos Password read error\n")
				return nil, err
                	}
        		fmt.Printf("\n")
                	configOut.Proxy.KerberosPass = string(bytePassword)
        	}
	} else {
		log.Printf("INFO: ReadConfig: NTLM and Kerberos details are not required with SSPI\n")
	}

        if configOut.Proxy.BasicUser != "" && configOut.Proxy.BasicPass == "" {
        	fmt.Printf("Enter Basic Password for %s: ",configOut.Proxy.BasicUser)
                bytePassword, err := term.ReadPassword(int(syscall.Stdin))
                if err != nil {
			log.Printf("ERROR: ReadConfig: Basic  Password read error\n")
			fmt.Printf("ReadConfig: Basic  Password read error\n")
			return nil, err
                }
        	fmt.Printf("\n")
                configOut.Proxy.BasicPass = string(bytePassword)
        }
	if configOut.Listen.IP == "" {
		configOut.Listen.IP = "127.0.0.1"
	}
	if configOut.Listen.Port == "" {
		configOut.Listen.Port = "9080"
	}
	if configOut.Logging.Level == "" {
		configOut.Logging.Level = "info"
	}
	return &configOut, nil
}
