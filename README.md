# GO myproxy proxy server based on httpproxy library

This is a proxy intended to be run in a user's context to be able to pass the user's authentication details to upstream proxies. 

It can read a Proxy Auto-Configuration file from local disk or a Web Server to determine the upstrem proxy or to go direct.

On Linux a user's Kerberos credentials can be provided or myproxy can read a user's Kerberos cache file ( FILE: format only for now ) for upstream proxy Negotiate authentication. 

On Linux a user's NTLM credentials can also be provided for upstream proxy NTLM authentication.

On Windows myproxy will use the SSPI interface i.e. no need to provide credentials for upstream proxy Negotiate and NTLM authentication. But if myproxy is run as a windows service the credentials will need to be provided for the service to logon with.

myproxy also supports upstrem proxy Basic authentication on Linux and Windows.

myproxy can read user passwords during startup instead of reading from YAML file.
 
myproxy logs to either stdout, a logfile, syslog(Linux) or event log(Windows). If run as a Windows service stdout is logged to c:\temp\myproxy_stdout.log.

On a multiuser system mproxy can user proxy Basic authentication to limit access to the myproxy port ( should only be used when listening on localhost ).

## Installing

```sh
git clone https://github.com/MMNetworks/myproxy.git

cd myproxy
go mod init myproxy
go mod tidy
go build myproxy.go version.go
```
### Linux

There are multiple ways to run myproxy. One option is to run it under systemd.  

Create a myproxy.services file in $HOME/.config/systemd/user


```sh
[Unit]
Description=Daemon for myproxy User Services

[Service]
Type=simple
#User=
#Group=
#ExecReload=/bin/kill -HUP $MAINPID
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
Make the YAML file only accessible by the user if passwords are kept in it  
Copy the PAC file into $HOME/.config/myproxy/conf if used  

Run:
  
systemctl --user daemon-reload  
systemctl --user enable myproxy.service 

The proxy should start when the user logs into the system  

if it doesn't you can start manually with:  
 
systemctl --user start myproxy.service  

P.S. Make sure that each user uses a different localhost port.

### Windows

The easiest way is to start myproxy during system startup when the user logs in. i.e. create a myproxy shortcut in the start-up directory 

![startup](startup.png)

myproxy can also be started as a service using the -a option. e.g.

myproxy.exe -a install  
myproxy.exe -a start

The service options are: install, start, autostart, manualstart, stop, pause, continue, status and remove.

The install will create the service as a manual started service. autostart and manualstart options will toggle this setting.

If started manually via the Service UI the start paramters -c \<configfile\> have to be provided.

### MacOS

On MacOS, you can run `myproxy` as a launchd service (agent) in your own user account, no need for root privileges.

First, create a `~/Library/LaunchAgents` directory.

Then create a plist file with a unique name (`com.${USER}.myproxy.plist` for instance) with the following contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>label</key>
        <string>com.<your-username>.myproxy</string>

        <key>ProgramArguments</key>
        <array>
                <string>/Users/<your-username>/bin/myproxy</string>
                <string>-c</string>
                <string>/Users/.config/myproxy/config/myprox.yaml</string>
        </array>

        <key>RunAtLoad</key>
        <true/>

        <key>KeepAlive</key>
        <true/>

        <key>StandardOutPath</key>
        <string>/tmp/myproxy.out</string>

        <key>StandardErrorPath</key>
        <string>/tmp/myproxy.err</string>
</dict>
</plist>

```

To install the service, run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.${USER}.proxy.plist`.

Please note that if you get any `launchctl` errors, you might need to `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.${USER}.proxy.plist` and bootstrap again because MacOS caches your plist file and won't be getting the fix.


## Usage

Configuration is stored in a YAML file and can be supplied with a -c argument  

When using myproxy as Windows service make sure the file paths are absolute paths.

<ul>
<li>logging:</li>
<ul>
<li>setting for proxy logging. Default stdout and info level and no function call trace</li>
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
<li>connection:</li>
<ul>
<li>setting for connection timeouts. readtimeout(deafult = 0) can enable longstanding session e.g. websockets. For granular control see websocket settings</li>
<li>When dns servers are specified the proxies own dial function is used instead of golangs default. The dns servers will be queried in parallel for fastest response ( no retry). The dialer tries connections over IPv6 first and then IPv4. If fallbackdelay is <= 0 the fastest response is selected from available IPv6 and IPv4 ips otherwise IPv4 will be delayed by fallbackdelay in milliseconds. The dialer can be limited to IPv6 or IPv4 only. </li>
<li>It supports DoT when prefixing DNS resolver IP with tls://</li>
<li>When selecting a DoH service i.e. prefix the DNS resolver with https:// it can be used over an upstream proxy. Any DNS loops will be avoided</li>
<li>You can select openDNS dns servers to apply category filtering.</li>
</ul>
<li>mitm:</li>
<ul>
<li>settings for TLS break of proxy connection.(default disabled) </li>
<li>needs either a string with key and certificate or file names pointing to a key and certficate</li>
<li>The rules list can be used to bypass TLS break </li>
<ul>
<li>        the IP is the source IP or subnet to include for TLS break or exclude if prefixed with !</li>
<li>        the client determines if the source IP is the connection IP or forwarded IP if set (client) or the source IP is only the connection IP when the forwarded IP is set(proxy) (i.e. connection IP is likely a downstream proxy). As default both IPs are checked against </li>
<li>        the regex is a regex to match the URL against.</li>
<li>        the certfile is a location of a selfsigned rootCA file. When MITM is enabled the proxy needs to verify the server cert instead of the client. This helps to limit selfsigned certificate checks. it can also be set to ignore certificate check with the keyword insecure</li>
</ul>
The rules file content will be appended to the rules list
</ul>
<li>wireshark:</li>
<ul>
<li>settings for wireshark listen ip and port. You can connect using wireshark -k -i TCP@&lt;ip&gt;:&lt;port&gt; </li>
<li>The rules list and the rules files can be used to limit access to wireshark listening port</li>
<li>There is also an option to send the unmasked websocket traffic to wireshark instead of the masked traffic</li>
</ul>
<li>clamd:</li>
<ul>
<li>settings for clamd connection. This can be a unix socket or over TCP and HTTPS. You have to provide a client cert and key for MTLS to the provided HTTPS server which converts HTTPS requests into clamd. This was added to make sure remote clamd connections are protected and authenticated.</li>
<li>clamd has also a setting to block virus infected traffic or only report and a setting to block when clamd is unavailable</li> 
</ul>
<li>websocket:</li>
<ul>
<li>settings to control websocket usage. The include/exclude list can be used to enable websocket per client and URL with a timeout. A timeout of 0 basically disables websockets. A default timeout can be set using the timeout setting. Websocket connections will also be inspected when MITM is set. Thw maximim websocket packet length can be set</li>
<ul>
<li>        the IP is source IP or subnet to include for websocket use or exclude if prefixed with !</li>
<li>        the client determines if the source IP is the connection IP or forwarded IP if set (client) or the source IP is only the connection IP when the forwarded IP is set(proxy) (i.e. connection IP is likely a downstream proxy). As default both IPs are checked against </li>
<li>        the regex is a regex to match the URL against.</li>
<li>        the timout is a timeout value in seconds</li>
</ul>
The rules file content will be appended to the rules list
</ul>
<li>ftp:</li>
<ul>
<li>setting default username / password for ftp. Default is anonymous / anonymous@myproxy
</ul>
</ul>

## YAML File format

```yaml
listen:
  ip: 127.0.0.1
  port: 9080
  tls: false
  certfile: "rootCA.crt"
  keyfile: "rootCA.key"
#  rootcafile: "CA.pem"
  rootcafile: "insecure"
  readtimeout: 0
  writetimeout: 0
  idletimeout: 300
wireshark:
  enable: true
  unmaskedwebsocket: true
  ip: 127.0.0.1
  port: 19000
  rulesfile: "wiresharkips.txt"
  rules:
     - "127.0.0.1/32"
clamd:
  enable: true
  block: true
  blockonerror: true
  connection: "unix:/var/run/clamav/clamd.ctl"
  certfile: "clientcert.pem"
  keyfile: "clientkey.pem"
  rootcafile: "rootca.pem"
logging:
  level: "debug"
  file: "log_9080"
  trace: false
  accesslog: "access.log"
  milliseconds: true 
connection:
  dnsservers: 
    - "tls://1.1.1.1"
    - "tls://1.1.1.1"
    - "https://dns.google"
    - "https://cloudflare-dns.com"
    - "https://dns.quad9.net"
    - "https://dns.adguard.com"
    - "https://dns.nextdns.io"
    - "1.1.1.1"
    - "8.8.8.8"
  dnstimeout: 2
  fallbackdelay: 300
  ipv6: true
  ipv4: true
  readtimeout: 0
  timeout: 5
  keepalive: 5
websocket:
  maxplength: 1048560
  timeout: 10
  rulesfile: "websocketrules.yaml"
  rules:
   - ip:  "127.0.0.1/32"
     regex: ".*"
     timeout: 30
   - ip:  "192.168.0.0/16"
     regex: ".*"
     timeout: 60
ftp:
  username: "ftp"
  password: "anonymous@ftp.com"
mitm:
  enable: false
  key: ""
  cert: ""
  keyfile: "key.pem"
  certfile: "cert.pem"
  rulesfile: "mitmrules.yaml"
  rules: 
    - ip: "::1"
      client: "client"
      regex: ".*"
      certfile: "insecure"
    - ip: "!100.10.10.0/24"
      regex: ".*"
      certfile: "selfsignedCA"
    - ip: "192.168.1.0/24"
      regex: ".*"
      certfile: "insecure"
    - ip: "0.0.0.0/0
      client: "client"
      regex: ".*"
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
  NTLMPass: "BetterProvidedOnCLI"
  KRBDomain: "TEST.COM"
  KRBMUser: "testuser"
  KRBPass: "BetterProvidedOnCLI"
  KRBCache: "/tmp/krb5cc_testuser"
  KRBConfig: "/etc/krb5.conf"
  BasicUser: "TestUser"
  BasicPass: "BetterProvidedOnCLI"
  LocalBasicUser: "TestUser"
  LocalBasicHash: "eb97d409396a3e5392936dad92b909da6f08d8c121a45e1f088fe9768b0c0339"
```
