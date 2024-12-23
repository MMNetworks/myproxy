package readconfig

import (
        "syscall"
        "golang.org/x/term"
	"gopkg.in/yaml.v3"
	"fmt"
	"log"
	"errors"
	"os"
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
}

func ReadConfig(configFilename string) *Schema {

	file, err := os.OpenFile(configFilename, os.O_RDONLY, 0600)

	if err != nil {
		log.Fatalf("error reading config: $%v", err)
		return nil
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var configOut = Schema{}
	err = decoder.Decode(&configOut)

	if err != nil {
		log.Fatalf("error decoding file: %v", err)
		os.Exit(1)
	}
	if configOut.PAC.Type != "FILE" && configOut.PAC.Type != "URL" {
		log.Printf("ERROR: ReadConfig: reading type field: %s", configOut.PAC.Type)
		log.Printf("ERROR: ReadConfig: only FILE and URL supported")
		os.Exit(1)
	}
	if configOut.PAC.Type == "FILE" && configOut.PAC.File == "" {
		log.Printf("ERROR: ReadConfig: reading type file: %s", configOut.PAC.File)
		log.Printf("ERROR: ReadConfig: FILE needs a filename")
		os.Exit(1)
	}
	if configOut.PAC.Type == "URL" && configOut.PAC.URL == "" {
		log.Printf("ERROR: ReadConfig: reading type url: %s", configOut.PAC.URL)
		log.Printf("ERROR: ReadConfig: URL needs a url")
		os.Exit(1)
	}
	for i, v := range configOut.Proxy.Authentication {
		if v != "ntlm" && v != "negotiate" && v != "basic" {
			log.Printf("ERROR: ReadConfig: reading authentication field: %d:%s\n", i+1, v)
			log.Printf("ERROR: ReadConfig: only ntln,negotiate and basic supported")
			os.Exit(1)
		}
	}
	if configOut.Proxy.NtlmUser != "" && configOut.Proxy.NtlmPass == "" {
        	fmt.Printf("Enter NTLM Password for %s: ",configOut.Proxy.NtlmUser)
        	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
        	if err != nil {
			log.Printf("ERROR: ReadConfig: NTLM Password read error")
			os.Exit(1)
        	}
        	fmt.Printf("\n")
        	configOut.Proxy.NtlmPass = string(bytePassword)
        }

	if configOut.Proxy.KerberosConfig != "" {
		_, err := os.Stat(configOut.Proxy.KerberosConfig)
		if errors.Is(err, os.ErrNotExist) ||  err != nil {
                        log.Printf("ERROR: ReadConfig: Can not read Kerberos config file %s",configOut.Proxy.KerberosConfig)
		}
	}

        if configOut.Proxy.KerberosUser != "" && configOut.Proxy.KerberosPass == "" && configOut.Proxy.KerberosCache == "" {
        	fmt.Printf("Enter Kerberos Password for %s: ",configOut.Proxy.KerberosUser)
                bytePassword, err := term.ReadPassword(int(syscall.Stdin))
                if err != nil {
                        log.Printf("ERROR: ReadConfig: Kerberos Password read error")
                        os.Exit(1)
                }
        	fmt.Printf("\n")
                configOut.Proxy.KerberosPass = string(bytePassword)
        }

        if configOut.Proxy.BasicUser != "" && configOut.Proxy.BasicPass == "" {
        	fmt.Printf("Enter Bsic Password for %s: ",configOut.Proxy.BasicUser)
                bytePassword, err := term.ReadPassword(int(syscall.Stdin))
                if err != nil {
                        log.Printf("ERROR: ReadConfig: Basic  Password read error")
                        os.Exit(1)
                }
        	fmt.Printf("\n")
                configOut.Proxy.BasicPass = string(bytePassword)
        }
	return &configOut
}
