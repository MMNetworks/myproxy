# GO myproxy proxy server based on httpproxy library

This is a proxy intended to be run in a users context to read user credentials for passing to upstream proxies. 

It can read a Proxy Auto-Configuration file from local disk or a Web Server to determine the upstrem proxy or go direct.

On Linux it can read a user's Kerberos cache file ( FILE: format only for now ) for upstream proxy Negotiate authentication. 

On Linux it can read a user's NTLM credentials for upstream proxy NTLM authentication.

On Windows it will use the SSPI interface for upstream proxy Negotiate and NTLM authentication.

The proxy also supports upstrem proxy Basic authentication on Linux and Windows.

myproxy can read user passwords during startup instead of reading from Yaml file.
 
It logs to either stdout, a logfile, syslog(Linux) or event log(Windows).

On a multiuser system proxy Basic authentication is supported to limit access to myproxy ( should only be used when listening on localhost ).

## Installing

```sh
git clone https://github.com/MMNetworks/myproxy.git

cd myproxy
go mod init myproxy
go mod tidy
go build myproxy.go
```
### Linux

There are multiple ways to run myproxy. One option is to run it under systemd.  

Create a myproxy.services file in $HOME/.config/systemd/user


```sh
[Unit]
Description=Script Daemon for myproxy User Services

[Service]
Type=simple
#User=
#Group=
ExecStart=%h/.config/myproxy/bin/myproxy -c %h/.config/myproxy/conf/myproxy.yaml
Restart=on-failure
StandardOutput=file:%h/.config/myproxy/log/myproxy_%u.log

[Install]
WantedBy=default.target
```

Create the following directory structure:

$HOME/.config/myproxy  
$HOME/.config/myproxy/bin  
$HOME/.config/myproxy/log  
$HOME/.config/myproxy/conf  

Copy the myproxy binary file into $HOME/.config/myproxy/bin
Copy the myproxy YAML config file into $HOME/.config/myproxy/conf  
Make the YAML file only accessible by the user if password are kept in it  
Copy the PAC file into $HOME/.config/myproxy/conf if used  

Run:
  
systemctl --user daemon-reload  
systemctl --user enable myproxy.service 

The proxy should start when the user logs into the system  

if it doesn't you can start manually with:  
 
systemctl --user start myproxy.service  


## Usage

Configuration is stored in a YAML file and can be supplied with a -c argument  

<ul>
<li>logging:</li>
<ul>
<li>setting for proxy logging. Default stdout and info level</li>
</ul>
<li>pac:</li>
<ul>
<li>setting for pac file. Reading from URL or FILE. Supports a proxy if PAC file is behind a proxy</li>
</ul>
<li>proxy:</li>
<ul>
<li>settings for upstream proxy. List of supported authentication methods in order of preference</li>
<li>LocalBasicUser and LocalBasicHash is used to authenticate to this proxy. Hash is created by createPwHash</li>
</ul>
</ul>

## YAML File format

```yaml
logging:
  level: "debug"
  file: "log_9080"
pac:
  type: "FILE"
  url: "http://pac.com/pac_file"
  file: "pac_file"
  proxy: "http://proxy.test.com:3128"
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
