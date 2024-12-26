# GO myproxy proxy server based on httpproxy library

This is a proxy intended to be run in a users context to read user credentials for passing to upstream proxies. 

It can read a Proxy Auto-Configuration file from local disk or a Web Server to determine the upstrem proxy or go direct.

On Linux it can read a user's Kerberos cache file ( FILE: format only for now ) for upstream proxy Negotiate authentication. 

On Linux it can read a user's NTLM credentials for upstream proxy NTLM authentication.

On Windows it will use the SSPI interface for upstream proxy Negotiate and NTLM authentication

The proxy also supports upstrem proxy Basic authentication on Linux and Windows
 
It logs to either stdout, a logfile, syslog(Linux) or event log(Windows)

On a multiuser system proxy Basic authentication is supported ( should only be used when listening on localhost ) 

## Installing

```sh
git clone https://github.com/MMNetworks/myproxy.git

cd myproxy
go mod init myproxy
go mod tidy
go build myproxy.go
```
## Usage

Configuration is stored in a YAML file and can be supplied with a -c argument

logging:    setting for proxy logging. Default stdout and info level
pac:        setting for pac file. Reading from URL or FILE. Supports a proxy of PAC file is behind a proxy.
proxy:      settings fro upstream proxy. List of supported authentication methods in order of preference
            LocalBasicUser and LocalBasicHash is used to authenticate to this proxy. Hash is created by createPwHash

## YAML File format

```yaml
logging:
  level: "debug"
  file: "log_9080"
pac:
  type: "FILE"
  url: "http://pac.com/pac_file"
  file: "pac_file"
  proxy: "http://proxy,test.com:3128"
proxy:
  authentication:
    - negotiate
    - ntlm
    - basic
  NTLMDomain: "TEST"
  NTLMUser: "testuser"
  NTLMPass: "BetterProvidedOnConsole"
  KRBDomain: "TEST.COM"
  KRBMUser: "testuser"
  KRBPass: "BetterProvidedOnConsole"
  KRBCache: "/tmp/krb5cc_testuser"
  KRBConfig: "/etc/krb5.conf"
  BasicUser: "TestUser"
  BasicPass: "BetterProvidedOnConsole"
  LocalBasicUser: "TestUser"
  LocalBasicHash: "eb97d409396a3e5392936dad92b909da6f08d8c121a45e1f088fe9768b0c0339"
```
