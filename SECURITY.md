# Security Considerations for myproxy

This document outlines security considerations and potential risks when using myproxy.

## TLS Certificate Verification

### Overview
myproxy allows disabling TLS certificate verification through the `"insecure"` configuration option. This setting is available in multiple contexts:

1. **MITM Rules** (`mitm.rules[].certfile: "insecure"`)
2. **DNS-over-HTTPS** (`connection.dnsservers` with `Connection.CAfile == "insecure"`)
3. **ClamAV Virus Scanner** (`clamd.rootcafile: "insecure"`)
4. **Listen Server** (`listen.rootcafile: "insecure"`)

### Security Risk: CRITICAL ⚠️

**When certificate verification is disabled (`InsecureSkipVerify: true`), the application is vulnerable to Man-in-the-Middle (MITM) attacks.**

An attacker can intercept TLS connections and present their own certificate without detection, allowing them to:
- Read all encrypted traffic
- Modify requests and responses
- Steal credentials and sensitive data
- Inject malicious content

### When is "insecure" Mode Acceptable?

The "insecure" mode should **ONLY** be used in these specific scenarios:

1. **Testing/Development Environments**
   - Testing with self-signed certificates
   - Local development without proper PKI infrastructure
   - **Never use in production**

2. **Internal Networks with Additional Security Layers**
   - Behind firewalls with strict access controls
   - When physical network security is guaranteed
   - With additional authentication mechanisms (mutual TLS, VPN, etc.)

3. **Legacy Systems**
   - Temporary workaround for systems with expired certificates
   - Should be remediated as soon as possible

### Recommendations

1. **Always use proper certificate validation in production**
   - Obtain valid certificates from trusted CAs
   - Use Let's Encrypt for free, automated certificates
   - Maintain a proper internal PKI for private networks

2. **For self-signed certificates**
   - Create a proper CA hierarchy
   - Distribute CA certificates to clients
   - Configure myproxy to use the CA bundle instead of "insecure"
   - See `create_CA.sh` for generating a CA

3. **Monitor and audit**
   - Log when "insecure" mode is enabled
   - Regularly review configurations
   - Set up alerts for certificate expiration

4. **Configuration example for proper certificate validation**
   ```yaml
   mitm:
     enable: true
     certfile: "rootCA.crt"  # NOT "insecure"
     keyfile: "rootCA.key"
     rules:
       - ip: "192.168.1.0/24"
         regex: ".*"
         certfile: "/path/to/ca-bundle.pem"  # Proper CA bundle
   ```

## Fixed Security Vulnerabilities

### 1. Insecure Random Number Generation (Fixed)

**Issue**: Previous versions used `math/rand` for cryptographic operations:
- Certificate private key generation (ECDSA keys)
- TCP sequence number initialization
- TLS certificate creation

**Impact**: 
- Predictable private keys could allow attackers to forge certificates
- Predictable TCP sequences could enable session hijacking attacks

**Fix**: Replaced with `crypto/rand` for cryptographically secure random generation:
- `casigner.go`: Now uses `crypto/rand.Reader` for all ECDSA key generation
- `wireshark.go`: Implemented `secureRandomUint32()` using `crypto/rand` for TCP sequences

**Version**: Fixed in commit aa82a58

### 2. Certificate Serial Number Generation

**Current Status**: Certificate serial numbers are derived from SHA-1 hash of hostnames

**Risk Level**: MEDIUM

**Impact**: While not immediately exploitable, deterministic serial numbers are:
- Predictable for the same hostname
- Less secure than random serial numbers
- Could aid in certificate tracking/fingerprinting

**Recommendation for Future**: Use `crypto/rand` to generate random serial numbers per RFC 5280

## No Race Conditions Found ✅

The codebase properly uses synchronization primitives:
- `sync.Mutex` for exclusive access to shared state
- `sync.RWMutex` for read-write patterns on certificate cache and config
- No unsynchronized access to shared maps or data structures detected

## Other Security Measures

### Already Implemented ✅

1. **Proper Authentication**
   - Multiple auth methods supported (Basic, NTLM, Kerberos)
   - Local proxy authentication with hashed passwords
   - See `credential/createPwHash.go` for password hashing

2. **No Command Injection**
   - No execution of external commands with user input
   - No shell command construction from untrusted data

3. **No SQL Injection**
   - No database operations in the codebase

4. **Path Traversal Protection**
   - Uses `filepath.Clean()` and `filepath.Abs()` for file operations
   - Validates file paths before use

5. **Sensitive Data Protection**
   - Passwords not logged directly
   - Only password lengths logged for debugging

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. Email the maintainers directly (see AUTHORS file)
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Security Best Practices for Deployment

1. **Run with least privileges**
   - Use dedicated user accounts
   - Restrict file permissions on configuration files
   - Set umask appropriately

2. **Network segmentation**
   - Run on localhost when possible
   - Use firewall rules to restrict access
   - Enable authentication (`LocalBasicUser` / `LocalBasicHash`)

3. **Keep updated**
   - Regularly update dependencies
   - Monitor for security advisories
   - Apply security patches promptly

4. **Configuration security**
   ```bash
   # Restrict config file permissions
   chmod 600 ~/.config/myproxy/conf/myproxy.yaml
   
   # Remove world-readable permissions on logs
   chmod 600 ~/.config/myproxy/log/*.log
   ```

5. **Use encrypted connections**
   - Enable TLS for the listen server
   - Use DoT/DoH for DNS resolution
   - Prefer HTTPS for all upstream connections

## Security Testing

Before deploying, verify:

1. Certificate validation works correctly
2. Authentication is required when configured
3. Logs don't expose sensitive data
4. File permissions are restrictive
5. Network access is properly limited

## Compliance Considerations

- **PCI DSS**: Do not use "insecure" mode for systems handling payment card data
- **HIPAA**: Do not use "insecure" mode for PHI/ePHI transmission
- **SOC 2**: Document and justify any use of "insecure" mode with compensating controls
- **ISO 27001**: Include TLS certificate management in ISMS

---

**Last Updated**: 2026-02-21  
**Version**: Based on commit aa82a58
