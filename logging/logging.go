package logging

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Followed RFC in using hex instead of decimal in same cases
//
// SSL 3.0 RFC 6101
// TLS 1.0 RFC 2246
// TLS 1.1 RFC 4346
// TLS 1.2 RFC 5246
// TLS 1.3 RFC 8446
// + RFC8701
var TLSString = map[string]string{
	"2":    "SSL 2.0",
	"300":  "SSL 3.0",
	"301":  "TLS 1.0",
	"302":  "TLS 1.1",
	"303":  "TLS 1.2",
	"304":  "TLS 1.3",
	"a0a":  "RFC8701",
	"1a1a": "RFC8701",
	"2a2a": "RFC8701",
	"3a3a": "RFC8701",
	"4a4a": "RFC8701",
	"5a5a": "RFC8701",
	"6a6a": "RFC8701",
	"7a7a": "RFC8701",
	"8a8a": "RFC8701",
	"9a9a": "RFC8701",
	"aaaa": "RFC8701",
	"baba": "RFC8701",
	"caca": "RFC8701",
	"dada": "RFC8701",
	"eaea": "RFC8701",
	"fafa": "RFC8701",
}

var TLSRecordType = map[uint8]string{
	0:  "invalid",
	20: "change_cipher_spec",
	21: "alert",
	22: "handshake",
	23: "application_data",
	24: "heartbeat",
}

var TLSHandshakeType = map[uint8]string{
	0:   "hello_request_RESERVED",
	1:   "client_hello",
	2:   "server_hello",
	3:   "hello_verify_request_RESERVED",
	4:   "new_session_ticket",
	5:   "end_of_early_data",
	6:   "hello_retry_request_RESERVED",
	8:   "encrypted_extensions",
	9:   "request_connection_id",
	10:  "new_connection_id",
	11:  "certificate",
	12:  "server_key_exchange_RESERVED",
	13:  "certificate_request",
	14:  "server_hello_done_RESERVED",
	15:  "certificate_verify",
	16:  "client_key_exchange_RESERVED",
	17:  "client_certificate_request",
	20:  "finished",
	21:  "certificate_url_RESERVED",
	22:  "certificate_status_RESERVED",
	23:  "supplemental_data_RESERVED",
	24:  "key_update",
	25:  "compressed_certificate",
	26:  "ekt_key",
	254: "message_hash",
}

// Cipher list from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
// + RFC8701
var TLSCipher = map[string]string{
	"0":    "TLS_NULL_WITH_NULL_NULL",
	"1":    "TLS_RSA_WITH_NULL_MD5",
	"2":    "TLS_RSA_WITH_NULL_SHA",
	"3":    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	"4":    "TLS_RSA_WITH_RC4_128_MD5",
	"5":    "TLS_RSA_WITH_RC4_128_SHA",
	"6":    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	"7":    "TLS_RSA_WITH_IDEA_CBC_SHA",
	"8":    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	"9":    "TLS_RSA_WITH_DES_CBC_SHA",
	"a":    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"b":    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	"c":    "TLS_DH_DSS_WITH_DES_CBC_SHA",
	"d":    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	"e":    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	"f":    "TLS_DH_RSA_WITH_DES_CBC_SHA",
	"10":   "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	"11":   "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	"12":   "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	"13":   "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	"14":   "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	"15":   "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	"16":   "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"17":   "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	"18":   "TLS_DH_anon_WITH_RC4_128_MD5",
	"19":   "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	"1a":   "TLS_DH_anon_WITH_DES_CBC_SHA",
	"1b":   "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	"1c":   "TLS_KRB5_WITH_DES_CBC_SHA",
	"1f":   "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
	"20":   "TLS_KRB5_WITH_RC4_128_SHA",
	"21":   "TLS_KRB5_WITH_IDEA_CBC_SHA",
	"22":   "TLS_KRB5_WITH_DES_CBC_MD5",
	"23":   "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
	"24":   "TLS_KRB5_WITH_RC4_128_MD5",
	"25":   "TLS_KRB5_WITH_IDEA_CBC_MD5",
	"26":   "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
	"27":   "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
	"28":   "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
	"29":   "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
	"2a":   "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
	"2b":   "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
	"2c":   "TLS_PSK_WITH_NULL_SHA",
	"2d":   "TLS_DHE_PSK_WITH_NULL_SHA",
	"2e":   "TLS_RSA_PSK_WITH_NULL_SHA",
	"2f":   "TLS_RSA_WITH_AES_128_CBC_SHA",
	"30":   "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	"31":   "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	"32":   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	"33":   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"34":   "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	"35":   "TLS_RSA_WITH_AES_256_CBC_SHA",
	"36":   "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	"37":   "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	"38":   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	"39":   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	"3a":   "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	"3b":   "TLS_RSA_WITH_NULL_SHA256",
	"3c":   "TLS_RSA_WITH_AES_128_CBC_SHA256",
	"3d":   "TLS_RSA_WITH_AES_256_CBC_SHA256",
	"3e":   "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	"3f":   "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	"40":   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	"41":   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	"42":   "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	"43":   "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	"44":   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	"45":   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	"46":   "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	"67":   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	"68":   "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	"69":   "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	"6a":   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	"6b":   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	"6c":   "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	"6d":   "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	"84":   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	"85":   "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	"86":   "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	"87":   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	"88":   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	"89":   "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	"8a":   "TLS_PSK_WITH_RC4_128_SHA",
	"8b":   "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
	"8c":   "TLS_PSK_WITH_AES_128_CBC_SHA",
	"8d":   "TLS_PSK_WITH_AES_256_CBC_SHA",
	"8e":   "TLS_DHE_PSK_WITH_RC4_128_SHA",
	"8f":   "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
	"90":   "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
	"91":   "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
	"92":   "TLS_RSA_PSK_WITH_RC4_128_SHA",
	"93":   "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
	"94":   "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
	"95":   "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
	"96":   "TLS_RSA_WITH_SEED_CBC_SHA",
	"97":   "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	"98":   "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	"99":   "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	"9a":   "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	"9b":   "TLS_DH_anon_WITH_SEED_CBC_SHA",
	"9c":   "TLS_RSA_WITH_AES_128_GCM_SHA256",
	"9d":   "TLS_RSA_WITH_AES_256_GCM_SHA384",
	"9e":   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"9f":   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	"a0":   "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	"a1":   "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	"a2":   "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	"a3":   "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	"a4":   "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	"a5":   "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	"a6":   "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	"a7":   "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	"a8":   "TLS_PSK_WITH_AES_128_GCM_SHA256",
	"a9":   "TLS_PSK_WITH_AES_256_GCM_SHA384",
	"aa":   "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
	"ab":   "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	"ac":   "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
	"ad":   "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
	"ae":   "TLS_PSK_WITH_AES_128_CBC_SHA256",
	"af":   "TLS_PSK_WITH_AES_256_CBC_SHA384",
	"b0":   "TLS_PSK_WITH_NULL_SHA256",
	"b1":   "TLS_PSK_WITH_NULL_SHA384",
	"b2":   "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
	"b3":   "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	"b4":   "TLS_DHE_PSK_WITH_NULL_SHA256",
	"b5":   "TLS_DHE_PSK_WITH_NULL_SHA384",
	"b6":   "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
	"b7":   "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
	"b8":   "TLS_RSA_PSK_WITH_NULL_SHA256",
	"b9":   "TLS_RSA_PSK_WITH_NULL_SHA384",
	"ba":   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	"bb":   "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	"bc":   "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	"bd":   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
	"be":   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	"bf":   "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
	"c0":   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	"c1":   "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	"c2":   "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	"c3":   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
	"c4":   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	"c5":   "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
	"c6":   "TLS_SM4_GCM_SM3",
	"c7":   "TLS_SM4_CCM_SM3",
	"ff":   "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	"1301": "TLS_AES_128_GCM_SHA256",
	"1302": "TLS_AES_256_GCM_SHA384",
	"1303": "TLS_CHACHA20_POLY1305_SHA256",
	"1304": "TLS_AES_128_CCM_SHA256",
	"1305": "TLS_AES_128_CCM_8_SHA256",
	"1306": "TLS_AEGIS_256_SHA512",
	"1307": "TLS_AEGIS_128L_SHA256",
	"5600": "TLS_FALLBACK_SCSV",
	"c001": "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	"c002": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	"c003": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	"c004": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	"c005": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	"c006": "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	"c007": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	"c008": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	"c009": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"c00a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"c00b": "TLS_ECDH_RSA_WITH_NULL_SHA",
	"c00c": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	"c00d": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	"c00e": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	"c00f": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	"c010": "TLS_ECDHE_RSA_WITH_NULL_SHA",
	"c011": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	"c012": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"c013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"c014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"c015": "TLS_ECDH_anon_WITH_NULL_SHA",
	"c016": "TLS_ECDH_anon_WITH_RC4_128_SHA",
	"c017": "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	"c018": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	"c019": "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	"c01a": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
	"c01b": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
	"c01c": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
	"c01d": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
	"c01e": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
	"c01f": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
	"c020": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
	"c021": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
	"c022": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
	"c023": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"c024": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	"c025": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	"c026": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	"c027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"c028": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	"c029": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	"c02a": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	"c02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"c02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"c02d": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	"c02e": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	"c02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"c030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"c031": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	"c032": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	"c033": "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
	"c034": "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
	"c035": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	"c036": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	"c037": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	"c038": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	"c039": "TLS_ECDHE_PSK_WITH_NULL_SHA",
	"c03a": "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	"c03b": "TLS_ECDHE_PSK_WITH_NULL_SHA384",
	"c03c": "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
	"c03d": "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
	"c03e": "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
	"c03f": "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
	"c040": "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
	"c041": "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
	"c042": "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
	"c043": "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
	"c044": "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
	"c045": "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
	"c046": "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
	"c047": "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
	"c048": "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
	"c049": "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
	"c04a": "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
	"c04b": "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
	"c04c": "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
	"c04d": "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
	"c04e": "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
	"c04f": "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
	"c050": "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
	"c051": "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
	"c052": "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
	"c053": "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
	"c054": "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
	"c055": "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
	"c056": "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
	"c057": "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
	"c058": "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
	"c059": "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
	"c05a": "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
	"c05b": "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
	"c05c": "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
	"c05d": "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	"c05e": "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
	"c05f": "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
	"c060": "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
	"c061": "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	"c062": "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
	"c063": "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
	"c064": "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
	"c065": "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
	"c066": "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
	"c067": "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
	"c068": "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
	"c069": "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
	"c06a": "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
	"c06b": "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
	"c06c": "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
	"c06d": "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
	"c06e": "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
	"c06f": "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
	"c070": "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
	"c071": "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
	"c072": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	"c073": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	"c074": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	"c075": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	"c076": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	"c077": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	"c078": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	"c079": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	"c07a": "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c07b": "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c07c": "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c07d": "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c07e": "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c07f": "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c080": "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	"c081": "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	"c082": "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	"c083": "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	"c084": "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
	"c085": "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
	"c086": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c087": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c088": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c089": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c08a": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c08b": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c08c": "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	"c08d": "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	"c08e": "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	"c08f": "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	"c090": "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	"c091": "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	"c092": "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
	"c093": "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
	"c094": "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	"c095": "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	"c096": "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	"c097": "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	"c098": "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	"c099": "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	"c09a": "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
	"c09b": "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
	"c09c": "TLS_RSA_WITH_AES_128_CCM",
	"c09d": "TLS_RSA_WITH_AES_256_CCM",
	"c09e": "TLS_DHE_RSA_WITH_AES_128_CCM",
	"c09f": "TLS_DHE_RSA_WITH_AES_256_CCM",
	"c0a0": "TLS_RSA_WITH_AES_128_CCM_8",
	"c0a1": "TLS_RSA_WITH_AES_256_CCM_8",
	"c0a2": "TLS_DHE_RSA_WITH_AES_128_CCM_8",
	"c0a3": "TLS_DHE_RSA_WITH_AES_256_CCM_8",
	"c0a4": "TLS_PSK_WITH_AES_128_CCM",
	"c0a5": "TLS_PSK_WITH_AES_256_CCM",
	"c0a6": "TLS_DHE_PSK_WITH_AES_128_CCM",
	"c0a7": "TLS_DHE_PSK_WITH_AES_256_CCM",
	"c0a8": "TLS_PSK_WITH_AES_128_CCM_8",
	"c0a9": "TLS_PSK_WITH_AES_256_CCM_8",
	"c0aa": "TLS_PSK_DHE_WITH_AES_128_CCM_8",
	"c0ab": "TLS_PSK_DHE_WITH_AES_256_CCM_8",
	"c0ac": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	"c0ad": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	"c0ae": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
	"c0af": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
	"c0b0": "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
	"c0b1": "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
	"c0b2": "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
	"c0b3": "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
	"c0b4": "TLS_SHA256_SHA256",
	"c0b5": "TLS_SHA384_SHA384",
	"c100": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
	"c101": "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
	"c102": "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
	"c103": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
	"c104": "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
	"c105": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
	"c106": "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
	"cca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"cca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"ccaa": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"ccab": "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	"ccac": "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	"ccad": "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	"ccae": "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
	"d001": "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
	"d002": "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	"d003": "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
	"d005": "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	"a0a":  "RFC8701",
	"1a1a": "RFC8701",
	"2a2a": "RFC8701",
	"3a3a": "RFC8701",
	"4a4a": "RFC8701",
	"5a5a": "RFC8701",
	"6a6a": "RFC8701",
	"7a7a": "RFC8701",
	"8a8a": "RFC8701",
	"9a9a": "RFC8701",
	"aaaa": "RFC8701",
	"baba": "RFC8701",
	"caca": "RFC8701",
	"dada": "RFC8701",
	"eaea": "RFC8701",
	"fafa": "RFC8701",
}

// from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
// +RFC8701
// + "TLS Application-Layer Protocol Settings Extension" - ihttps://github.com/vasilvv/tls-alps/blob/main/draft-vvv-tls-alps.md
var TLSExtensionType = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	25:    "cached_info",
	26:    "tls_lts",
	27:    "compress_certificate",
	28:    "record_size_limit",
	29:    "pwd_protect",
	30:    "pwd_clear",
	31:    "password_salt",
	32:    "ticket_pinning",
	33:    "tls_cert_with_extern_psk",
	34:    "delegated_credential",
	35:    "session_ticket",
	36:    "TLMSP",
	37:    "TLMSP_proxying",
	38:    "TLMSP_delegate",
	39:    "supported_ekt_ciphers",
	40:    "Reserved",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	46:    "Reserved",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	52:    "transparency_info",
	53:    "connection_id_deprecated",
	54:    "connection_id",
	55:    "external_id_hash",
	56:    "external_session_id",
	57:    "quic_transport_parameters",
	58:    "ticket_request",
	59:    "dnssec_chain",
	60:    "sequence_number_encryption_algorithms",
	61:    "rrc",
	62:    "tls_flags",
	17613: "ApplicationSettingsSupport", // Draft
	13172: "next_protocol_negotiation",  // Not IANA assigned !!
	64768: "ech_outer_extensions",
	65037: "encrypted_client_hello",
	65281: "renegotiation_info",
	2570:  "RFC8701",
	6682:  "RFC8701",
	10794: "RFC8701",
	14906: "RFC8701",
	19018: "RFC8701",
	23130: "RFC8701",
	27242: "RFC8701",
	31354: "RFC8701",
	35466: "RFC8701",
	39578: "RFC8701",
	43690: "RFC8701",
	47802: "RFC8701",
	51914: "RFC8701",
	56026: "RFC8701",
	60138: "RFC8701",
	64250: "RFC8701",
}

type ReadConfig interface {
	LogLevel() string
	LogTrace() bool
	LogFile() string
	AccessFile() string
	MilliSeconds() bool
}

type logStruct struct {
	time     string
	filename string
	level    string
	message  string
}

// Logging Configuration
type configStruct struct {
	Mu          sync.Mutex
	logLevel    string
	logTrace    bool
	logFilename string
	accessLog   string
	msec        bool
}

var current configStruct

var logChan = make(chan logStruct, 65000) // Buffered channel

func LogProcessor(readConfig ReadConfig) {
	var logBuffer *bufio.Writer
	var accessBuffer *bufio.Writer
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var logFile *os.File
	var accessLogFile *os.File

	// Buffer writing to OS files

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)

	// Use interface to avoid import loop
	current.Mu.Lock()
	current.msec = readConfig.MilliSeconds()
	current.logLevel = strings.ToUpper(readConfig.LogLevel())
	current.logTrace = readConfig.LogTrace()
	current.logFilename = readConfig.LogFile()
	current.accessLog = readConfig.AccessFile()
	current.Mu.Unlock()

	for {
		if strings.ToUpper(current.logFilename) != "STDOUT" && current.logFilename != "" {
			if strings.ToUpper(current.logFilename) != "SYSLOG" && strings.ToUpper(current.logFilename) != "EVENTLOG" {
				// Log buffered to local Unix file
				var err error
				logFile, err = os.OpenFile(current.logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
				if err != nil {
					timeStamp := time.Now().Format(time.RFC1123)
					fmt.Printf("%s ERROR: LogProcessor: Could not open logfile %s\n", timeStamp, current.logFilename)
					return
				}
				defer logFile.Close()
				logBuffer = bufio.NewWriterSize(logFile, 64*1024) // 64KB buffer
			} // else write to system log
		} else {
			// Log buffered to stdout
			current.Mu.Lock()
			current.logFilename = "STDOUT"
			current.Mu.Unlock()
			logBuffer = bufio.NewWriterSize(os.Stdout, 64*1024) // 64KB buffer
		}
		if strings.ToUpper(current.accessLog) != "STDOUT" && current.accessLog != "" {
			if strings.ToUpper(current.accessLog) != "SYSLOG" && strings.ToUpper(current.accessLog) != "EVENTLOG" {
				// Log buffered to local Unix file
				var err error
				accessLogFile, err = os.OpenFile(current.accessLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
				if err != nil {
					timeStamp := time.Now().Format(time.RFC1123)
					fmt.Printf("%s ERROR: LogProcessor: Could not open accesslog file %s\n", timeStamp, current.accessLog)
					return
				}
				defer accessLogFile.Close()
				accessBuffer = bufio.NewWriterSize(accessLogFile, 64*1024) // 64KB buffer
			} // else write to sysetm log
		} else {
			// Log buffered to stdout
			current.accessLog = "STDOUT"
			accessBuffer = bufio.NewWriterSize(os.Stdout, 64*1024) // 64KB buffer
		}

	flush:
		for {
			select {
			case s := <-sig:
				if s == syscall.SIGHUP {
					logBuffer.Flush()
					accessBuffer.Flush()
					logFile.Close()
					accessLogFile.Close()
					// read new file name
					break flush
				}
			case lStruct, ok := <-logChan:
				if !ok {
					logBuffer.Flush()
					accessBuffer.Flush()
					timeStamp := time.Now().Format(time.RFC1123)
					fmt.Printf("%s ERROR: LogProcessor: channel error\n", timeStamp)
					return
				}
				if strings.ToUpper(lStruct.filename) == "SYSLOG" || strings.ToUpper(lStruct.filename) == "EVENTLOG" {
					_systemLog(lStruct.time, lStruct.level, "%s", lStruct.message)
				} else {
					if strings.ToUpper(lStruct.filename) == strings.ToUpper(current.logFilename) {
						_osPrintf(lStruct.time, logBuffer, lStruct.level, "%s", lStruct.message)
					} else if strings.ToUpper(lStruct.filename) == strings.ToUpper(current.accessLog) {
						_osPrintf(lStruct.time, accessBuffer, lStruct.level, "%s", lStruct.message)
					} else {
						_osPrintf(lStruct.time, logBuffer, "ERROR", "%s", "ERROR: Unkown log file "+lStruct.filename+"\n")
					}
				}
			case <-ticker.C:
				logBuffer.Flush()    // periodic flush
				accessBuffer.Flush() // periodic flush
			}
		}
	}
}

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)
	return fn.Name()
}

func Printf(level string, format string, a ...any) (int, error) {
	message := fmt.Sprintf(format, a...)
	formatString := time.RFC1123
	current.Mu.Lock()
	defer current.Mu.Unlock()
	if current.msec {
		formatString = "Mon, 02 Jan 2006 15:04:05.000 MST"
	}

	timeStamp := time.Now().Format(formatString)
	line := logStruct{time: timeStamp, filename: current.logFilename, level: level, message: message}
	length := len(level + ": " + message)

	logChan <- line

	return length, nil
}

func osPrintf(logFilename string, level string, format string, a ...any) (int, error) {
	message := fmt.Sprintf(format, a...)
	timeStamp := time.Now().Format(time.RFC1123)
	line := logStruct{time: timeStamp, filename: logFilename, level: level, message: message}
	length := len(level + ": " + message)

	logChan <- line

	return length, nil
}

func _osPrintf(timeStamp string, logBuffer *bufio.Writer, level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil

	current.Mu.Lock()
	defer current.Mu.Unlock()
	message := fmt.Sprintf(format, a...)
	if level == "INFO" {
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO":
			length, err = fmt.Fprintf(logBuffer, "%s INFO: %s", timeStamp, message)
		default:
		}
	} else if level == "DEBUG" {
		switch {
		case
			current.logLevel == "DEBUG":
			length, err = fmt.Fprintf(logBuffer, "%s DEBUG: %s", timeStamp, message)
		default:
		}
	} else if level == "WARNING" {
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO",
			current.logLevel == "WARNING":
			length, err = fmt.Fprintf(logBuffer, "%s WARNING: %s", timeStamp, message)
		default:
		}
	} else if level == "ERROR" {
		length, err = fmt.Fprintf(logBuffer, "%s ERROR: %s", timeStamp, message)
	} else if level == "ACCESS" || level == "STARTLOG" {
		length, err = fmt.Fprintf(logBuffer, "%s %s: %s", timeStamp, level, message)
	} else if level == "TRACE" {
		if current.logTrace {
			length, err = fmt.Fprintf(logBuffer, "%s TRACE: %s", timeStamp, message)
		}
	} else {
		length, err = fmt.Fprintf(logBuffer, "%s UNKNOWN: %s", timeStamp, message)
	}
	return length, err
}
