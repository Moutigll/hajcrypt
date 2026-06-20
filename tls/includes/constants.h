#ifndef BTLS_CONSTANTS_H
# define BTLS_CONSTANTS_H

# include "../../includes/asymmetric/pkey.h"
# include "../../includes/asymmetric/kex.h"
# include "../../includes/cipher/cipher.h"
# include "../../includes/cipher/aes.h"
# include "../../includes/cipher/chacha20Poly1305.h"
# include "../../includes/hash/hash.h"


# define BTLS_DEBUG(string, ...) ft_printf("[BTLS]: " string "\n", ##__VA_ARGS__)


typedef enum e_tlsVersionSupported {
	TLS_VERS_1_0 = 0b0001,
	TLS_VERS_1_1 = 0b0010,
	TLS_VERS_1_2 = 0b0100,
	TLS_VERS_1_3 = 0b1000
}	t_tlsVersionSupported;

typedef enum e_tlsRecordCipherType
{
	BTLS_RECORD_AEAD,
	BTLS_RECORD_CBC_HMAC,
	BTLS_RECORD_STREAM		/* Not supported as it is strongly deprecated */
}	t_tlsRecordCipherType;

typedef enum e_tlsCipherType
{
	BTLS_CIPHER_AES_128_GCM,
	BTLS_CIPHER_AES_256_GCM,
	BTLS_CIPHER_CHACHA20_POLY1305,
	BTLS_CIPHER_AES_128_CBC,
	BTLS_CIPHER_AES_256_CBC,
	BTLS_CIPHER_DES_CBC,
	BTLS_CIPHER_3DES_EDE_CBC,
	BTLS_CIPHER_UNKNOWN
}	t_tlsCipherType;

typedef struct s_tlsGroup {
	uint16_t	wireValue;
	t_kexType	kexType;
	int			groupId;
	const char	*name;
	uint8_t		supportedVersions;
} t_tlsGroup;

/**
 * @brief Unified AEAD cipher context
 *
 * This structure abstracts the differences between AES-GCM and
 * ChaCha20-Poly1305, providing a common interface for TLS record
 * protection. The union stores the cipher-specific context while
 * the common fields track metadata and cached key material for
 * potential re-initialization or key updates.
 */
typedef struct s_aeadCipher
{
	size_t			keySize;
	size_t			ivSize;
	size_t			tagLen;
}	t_aeadCipher;

typedef struct s_tlsCipherSuite {
	uint16_t				wireValue;			/* Cipher suite identifier as defined in RFC 8446 */
	const char				*name;				/* Human-readable name of the cipher suite */
	t_tlsCipherType			cipherType;			/* Cipher type (AES-GCM, ChaCha20-Poly1305, etc.) */
	t_tlsRecordCipherType	recordCipherType;	/* Record cipher type (AEAD, CBC+HMAC, Stream) */
	const t_kexType			kex;				/* Key exchange algorithm (ECDHE/DHE) */
	const t_pkeyDef			*pkey;				/* Pointer to the public key definition (for RSA, ECDSA, etc.) */
	union
	{
		const t_cipher		*cipher;			/* Pointer to the cipher definition (for CBC or AEAD) */
		const t_aeadCipher	*aeadCipher;		/* Pointer to the AEAD cipher definition (for AEAD ciphers) */
	} cipher;
	const t_hash			*hash;				/* Pointer to the hash definition (for HMAC or AEAD) */
	uint8_t					supportedVersions;	/* Bitmask of supported TLS versions (e.g., TLS_VERS_1_2 | TLS_VERS_1_3) */
} t_tlsCipherSuite;

typedef struct s_tlsSignatureAlgorithm {
	uint16_t		wireValue;
	const t_hash	*hash;
	const t_pkeyDef	*pkey;
	const char		*name;
	uint8_t			supportedVersions;
} t_tlsSigAlgo;


/* TLS version identifiers */
#define TLS_VERSION_1_0	0x0301
#define TLS_VERSION_1_1	0x0302
#define TLS_VERSION_1_2	0x0303
#define TLS_VERSION_1_3	0x0304

#define TLS_LEGACY_VERSION	0x0303	/* Used in record headers for TLS 1.2 compatibility */

typedef enum e_tlsAlertLevel {
	TLS_ALERT_LEVEL_NORMAL = 0,
	TLS_ALERT_LEVEL_WARNING = 1,
	TLS_ALERT_LEVEL_FATAL = 2
}	t_tlsAlertLevel;

/* TLS alert descriptions */
/* TLS alert levels */
#define TLS_ALERT_LEVEL_WARNING    1
#define TLS_ALERT_LEVEL_FATAL      2

/* TLS alert descriptions (RFC 8446) */
#define TLS_ALERT_CLOSE_NOTIFY				0x00
#define TLS_ALERT_UNEXPECTED_MESSAGE		0x0A
#define TLS_ALERT_BAD_RECORD_MAC			0x14
#define TLS_ALERT_DECRYPTION_FAILED			0x15
#define TLS_ALERT_RECORD_OVERFLOW			0x16
#define TLS_ALERT_HANDSHAKE_FAILURE			0x28
#define TLS_ALERT_NO_CERTIFICATE			0x29
#define TLS_ALERT_BAD_CERTIFICATE			0x2A
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE	0x2B
#define TLS_ALERT_CERTIFICATE_REVOKED		0x2C
#define TLS_ALERT_CERTIFICATE_EXPIRED		0x2D
#define TLS_ALERT_CERTIFICATE_UNKNOWN		0x2E
#define TLS_ALERT_ILLEGAL_PARAMETER			0x2F
#define TLS_ALERT_UNKNOWN_CA				0x30
#define TLS_ALERT_ACCESS_DENIED				0x31
#define TLS_ALERT_DECODE_ERROR				0x32
#define TLS_ALERT_DECRYPT_ERROR				0x33
#define TLS_ALERT_PROTOCOL_VERSION			0x46
#define TLS_ALERT_INSUFFICIENT_SECURITY		0x47
#define TLS_ALERT_INTERNAL_ERROR			0x50
#define TLS_ALERT_USER_CANCELED				0x5A
#define TLS_ALERT_NO_RENEGOTIATION			0x64
#define TLS_ALERT_MISSING_EXTENSION			0x6D
#define TLS_ALERT_UNSUPPORTED_EXTENSION		0x6E
#define TLS_ALERT_ECH_REQUIRED				0x6F
#define TLS_ALERT_CERTIFICATE_REQUIRED		0x70
#define TLS_ALERT_RECORD_LIMIT_EXCEEDED		0x75
#define TLS_ALERT_NO_APPLICATION_PROTOCOL	0x78

/* TLS handshake message types */
#define TLS_HT_HELLO_REQUEST				0
#define TLS_HT_CLIENT_HELLO					1
#define TLS_HT_SERVER_HELLO					2
#define TLS_HT_NEW_SESSION_TICKET			4
#define TLS_HT_END_OF_EARLY_DATA			5
#define TLS_HT_HELLO_RETRY_REQUEST			6
#define TLS_HT_ENCRYPTED_EXTENSIONS			8
#define TLS_HT_CERTIFICATE					11
#define TLS_HT_CERTIFICATE_REQUEST			13
#define TLS_HT_CERTIFICATE_VERIFY			15
#define TLS_HT_FINISHED						20
#define TLS_HT_KEY_UPDATE					24
#define TLS_HT_MESSAGE_HASH					254

/* TLS record content types */
#define TLS_RT_CHANGE_CIPHER_SPEC	0x14
#define TLS_RT_ALERT				0x15
#define TLS_RT_HANDSHAKE			0x16
#define TLS_RT_APPLICATION_DATA		0x17

/* TLS record header size */
#define TLS_RECORD_HEADER_SIZE		5

/* Maximum fragment length (2^14) */
#define TLS_MAX_FRAGMENT_LEN		16384

/* ===== TLS extensions ===== */

/* ===== TLS 1.3 extensions ===== */
# define TLS_EXT_COMPRESS_CERTIFICATE		27		/* Certificate compression (TLS 1.3) */
# define TLS_EXT_DELEGATED_CREDENTIAL		34		/* Delegated credentials (TLS 1.3) */
# define TLS_EXT_PRE_SHARED_KEY				41		/* Pre-shared key (TLS 1.3) */
# define TLS_EXT_EARLY_DATA					42		/* Early data (0-RTT) (TLS 1.3) */
# define TLS_EXT_SUPPORTED_VERSIONS			43		/* Supported versions (TLS 1.3) */
# define TLS_EXT_PSK_KEY_EXCHANGE_MODES		45		/* PSK key exchange modes (TLS 1.3) */
# define TLS_EXT_CERTIFICATE_AUTHORITIES	47		/* Certificate authorities (TLS 1.3) */
# define TLS_EXT_OID_FILTERS				48		/* OID filters (TLS 1.3) */
# define TLS_EXT_POST_HANDSHAKE_AUTH		49		/* Post-handshake auth (TLS 1.3) */
# define TLS_EXT_SIGNATURE_ALGORITHMS_CERT	50		/* Signature algorithms for certificates (TLS 1.3) */
# define TLS_EXT_KEY_SHARE					51		/* Key share (TLS 1.3) */
# define TLS_EXT_QUIC_TRANSPORT_PARAMS		57		/* QUIC transport params (TLS 1.3) */
# define TLS_EXT_DNSSEC_CHAIN				59		/* DNSSEC chain (RFC 9150) */
# define TLS_EXT_SNEA						60		/* Sequence number encryption algorithms (TLS 1.3) */
# define TLS_EXT_TLS_FLAGS					62		/* TLS flags (draft-ietf-tls-tlsflags) */
# define TLS_EXT_ECH_OUTER_EXTENSIONS		64768	/* ECH outer extensions (TLS 1.3) */
# define TLS_EXT_ENCRYPTED_CLIENT_HELLO		65037	/* Encrypted Client Hello (ECH) (TLS 1.3) */

/* ===== DTLS extensions ===== */
# define TLS_EXT_COOKIE						44		/* DTLS cookie */
# define TLS_EXT_CONNECTION_ID				54		/* Connection ID (DTLS) */
# define TLS_EXT_RRC						61		/* RRC (RFC 9853) */

/* ===== TLS 1.2 and TLS 1.3 shared extensions ===== */
# define TLS_EXT_SERVER_NAME				0		/* Server Name Indication (SNI) */
# define TLS_EXT_MAX_FRAGMENT_LENGTH		1		/* Max fragment length */
# define TLS_EXT_TRUSTED_CA_KEYS			3		/* Trusted CA keys (deprecated) */
# define TLS_EXT_STATUS_REQUEST				5		/* OCSP stapling (status_request) */
# define TLS_EXT_USER_MAPPING				6		/* User mapping (RFC 4681) */
# define TLS_EXT_CLIENT_AUTHZ				7		/* Client authz (RFC 5878) */
# define TLS_EXT_SERVER_AUTHZ				8		/* Server authz (RFC 5878) */
# define TLS_EXT_CERT_TYPE					9		/* Client certificate type (RFC 7250) */
# define TLS_EXT_SUPPORTED_GROUPS			10		/* Supported groups (EC/DH) */
# define TLS_EXT_EC_POINT_FORMATS			11		/* EC point formats */
# define TLS_EXT_SRP						12		/* Secure Remote Password */
# define TLS_EXT_SIGNATURE_ALGORITHMS		13		/* Signature algorithms */
# define TLS_EXT_USE_SRTP					14		/* SRTP protection profiles */
# define TLS_EXT_HEARTBEAT					15		/* Heartbeat (RFC 6520) */
# define TLS_EXT_ALPN						16		/* Application-Layer Protocol Negotiation */
# define TLS_EXT_STATUS_REQUEST_V2			17		/* OCSP stapling v2 (multiple responses) */
# define TLS_EXT_SIGNED_CERT_TIMESTAMP		18		/* Signed Certificate Timestamp (RFC 6962) */
# define TLS_EXT_CLIENT_CERTIFICATE_TYPE	19		/* Client certificate type (RFC 7250) */
# define TLS_EXT_SERVER_CERTIFICATE_TYPE	20		/* Server certificate type (RFC 7250) */
# define TLS_EXT_PADDING					21		/* Padding (RFC 7685) */
# define TLS_EXT_TOKEN_BINDING				24		/* Token binding (RFC 8472) */
# define TLS_EXT_CACHED_INFO				25		/* Cached info (RFC 7924) */
# define TLS_EXT_TLS_LTS					26		/* TLS long-term support (RFC 8797) */
# define TLS_EXT_RECORD_SIZE_LIMIT			28		/* Record size limit (TLS 1.3) */
# define TLS_EXT_PWD_PROTECT				29		/* Password protected (RFC 8125) */
# define TLS_EXT_PWD_CLEAR					30		/* Password clear (RFC 8125) */
# define TLS_EXT_PASSWORD_SALT				31		/* Password salt (RFC 8125) */
# define TLS_EXT_TICKET_PINNING				32		/* Ticket pinning (RFC 8672) */
# define TLS_EXT_TLS_CERT_WITH_EXTERN_PSK	33		/* Certificate with external PSK (TLS 1.3) */
# define TLS_EXT_SESSION_TICKET				35		/* Session ticket (RFC 5077) */
# define TLS_EXT_TLSP						36		/* TLS session resumption with PSK (draft-ietf-tls-tlsp) */
# define TLS_EXT_TLSP_PROXYING				37		/* TLS session resumption with PSK proxying (draft-ietf-tls-tlsp) */
# define TLS_EXT_TLSP_DELEGATE				38		/* TLS session resumption with PSK delegation (draft-ietf-tls-tlsp) */
# define TLS_EXT_SUPPORTED_EKT_CIPHERS		39		/* Supported EKT ciphers (RFC 8870) */
# define TLS_EXT_TRANSPARENCY_INFO			52		/* Certificate transparency info (RFC 9162) */
# define TLS_EXT_CONNECTION_ID_DEPRECATED	53		/* Connection ID (deprecated in TLS 1.3) */
# define TLS_EXT_EXTERNAL_ID_HASH			55		/* External ID hash (RFC 8844) */
# define TLS_EXT_EXTERNAL_SESSION_ID		56		/* External session ID (RFC 8844) */
# define TLS_EXT_TICKET_REQUEST				58		/* Ticket request (RFC 9149) */

/* ===== TLS 1.2 extensions (deprecated in TLS 1.3) ===== */
# define TLS_EXT_TRUNCATED_HMAC				4		/* Truncated HMAC (TLS 1.2) */
# define TLS_EXT_ENCRYPT_THEN_MAC			22		/* Encrypt-then-MAC (TLS 1.2) */
# define TLS_EXT_EXTENDED_MASTER_SECRET		23		/* Extended master secret (TLS 1.2) */

/* Labels TLS 1.3 */
#define TLS13_LABEL_DERIVED				"derived"
#define TLS13_LABEL_EXTRACTOR			"ext binder"
#define TLS13_LABEL_HANDSHAKE			"handshake"
#define TLS13_LABEL_CLIENT_HS_TRAFFIC	"c hs traffic"
#define TLS13_LABEL_SERVER_HS_TRAFFIC	"s hs traffic"
#define TLS13_LABEL_CLIENT_APP_TRAFFIC	"c ap traffic"
#define TLS13_LABEL_SERVER_APP_TRAFFIC	"s ap traffic"
#define TLS13_LABEL_EXPORTER_MASTER		"exp master"
#define TLS13_LABEL_RESUMPTION_MASTER	"res master"
#define TLS13_LABEL_TRAFFIC_KEY			"key"
#define TLS13_LABEL_TRAFFIC_IV			"iv"
#define TLS13_LABEL_FINISHED			"finished"

/* TLS named groups */
#define TLS_NAMED_GROUP_SECP256R1	0x0017
#define TLS_NAMED_GROUP_SECP384R1	0x0018
#define TLS_NAMED_GROUP_SECP521R1	0x0019
#define TLS_NAMED_GROUP_X25519		0x001D
#define TLS_NAMED_GROUP_X448		0x001E
#define TLS_NAMED_GROUP_FFDHE2048	0x0100
#define TLS_NAMED_GROUP_FFDHE3072	0x0101
#define TLS_NAMED_GROUP_FFDHE4096	0x0102
#define TLS_NAMED_GROUP_FFDHE6144	0x0103
#define TLS_NAMED_GROUP_FFDHE8192	0x0104



/* TLS cipher suite identifiers */

/* TLS 1.3 cipher suites (RFC 8446) */
#define TLS_CIPHER_AES_128_GCM			0x1301
#define TLS_CIPHER_AES_256_GCM			0x1302
#define TLS_CIPHER_CHACHA20_POLY1305	0x1303

/* TLS 1.2 cipher suites (RFC 5246, RFC 5289, RFC 8422, RFC 7905) */

/* RSA */
#define TLS_RSA_WITH_AES_128_CBC_SHA	0x002F
#define TLS_RSA_WITH_AES_256_CBC_SHA	0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256	0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256	0x003D
#define TLS_RSA_WITH_AES_128_GCM_SHA256	0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384	0x009D

/* DHE_RSA */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA	0x0033
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA	0x0039
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256	0x0067
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256	0x006B
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256	0x009E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384	0x009F

/* ECDHE_ECDSA */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	0xC009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	0xC00A
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	0xC023
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384	0xC024
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	0xC02C

/* ECDHE_RSA */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA		0xC013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA		0xC014
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	0xC027
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	0xC028
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030

/* DHE_DSA */
#define TLS_DHE_DSA_WITH_AES_128_CBC_SHA256	0x0068
#define TLS_DHE_DSA_WITH_AES_256_CBC_SHA256	0x006C
#define TLS_DHE_DSA_WITH_AES_128_GCM_SHA256	0x00A2
#define TLS_DHE_DSA_WITH_AES_256_GCM_SHA384	0x00A3

/* ChaCha20-Poly1305 (RFC 7905) */
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256		0xCCA8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	0xCCA9
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256		0xCCAA

/* Obsolete / weak (DES, 3DES) – RFC 5246 */
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA	0x0016
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA		0x000A
#define TLS_DHE_RSA_WITH_DES_CBC_SHA		0x0015
#define TLS_RSA_WITH_DES_CBC_SHA			0x0009

/* TLS signature algorithms */
#define TLS_SIG_RSA_PKCS1_SHA1			0x0201
#define TLS_SIG_DSA_SHA1				0x0202
#define TLS_SIG_ECDSA_SHA1				0x0203
#define TLS_SIG_RSA_PKCS1_SHA256		0x0401
#define TLS_SIG_DSA_SHA256				0x0402
#define TLS_SIG_ECDSA_SECP256R1_SHA256	0x0403
#define TLS_SIG_RSA_PKCS1_SHA384		0x0501
#define TLS_SIG_DSA_SHA384				0x0502
#define TLS_SIG_ECDSA_SECP384R1_SHA384	0x0503
#define TLS_SIG_RSA_PKCS1_SHA512		0x0601
#define TLS_SIG_DSA_SHA512				0x0602
#define TLS_SIG_ECDSA_SECP521R1_SHA512	0x0603
#define TLS_SIG_RSA_PSS_RSAE_SHA256		0x0804
#define TLS_SIG_RSA_PSS_RSAE_SHA384		0x0805
#define TLS_SIG_RSA_PSS_RSAE_SHA512		0x0806
#define TLS_SIG_RSA_PSS_PSS_SHA256		0x0807
#define TLS_SIG_RSA_PSS_PSS_SHA384		0x0808
#define TLS_SIG_RSA_PSS_PSS_SHA512		0x0809


size_t					getSupportedGroupsWire(uint16_t *out, size_t maxGroups, uint8_t tlsVersion);
int						negotiateGroup(const uint16_t *clientGroups, size_t clientCount, uint16_t *selectedWire, int *kexType, int *groupId);

size_t					getSupportedCipherSuitesWire(uint16_t *out, size_t maxSuites, uint8_t tlsVersion);
const t_tlsCipherSuite	*negotiateCipherSuite(const uint16_t *clientSuites, size_t clientCount);

size_t					getSupportedSignatureAlgorithmsWire(uint16_t *out, size_t maxAlgs, uint8_t tlsVersion);
const t_tlsSigAlgo		*negotiateSignatureAlgorithm(const uint16_t *clientAlgs, size_t clientCount);

const t_tlsGroup		*getGroup(uint16_t wireValue);
const t_tlsCipherSuite	*getCipherSuite(uint16_t wireValue);
const t_tlsSigAlgo		*getSigAlgo(uint16_t wireValue);

extern const t_tlsGroup			g_supportedGroups[];
extern const t_tlsCipherSuite	g_supportedCipherSuites[];
extern const t_tlsSigAlgo		g_supportedSignatureAlgorithms[];

#endif /* BTLS_CONSTANTS_H */
