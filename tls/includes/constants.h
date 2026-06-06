#ifndef TLS_CONSTANTS_H
# define TLS_CONSTANTS_H

# include "../../includes/asymmetric/pkey.h"
# include "../../includes/hash/hash.h"
# include "aeadCipher.h"

typedef enum e_tlsVersionSupported {
	TLS_VERS_1_0 = 0b0001,
	TLS_VERS_1_1 = 0b0010,
	TLS_VERS_1_2 = 0b0100,
	TLS_VERS_1_3 = 0b1000
}	t_tlsVersionSupported;

typedef struct s_tlsGroup {
	uint16_t	wireValue;
	int			kexType;
	int			groupId;
	const char	*name;
	uint8_t		supportedVersions;
} t_tlsGroup;

typedef struct s_tlsCipherSuite {
	uint16_t			wireValue;
	t_tlsCipherType		cipher;
	const char			*name;
	const t_hashAlgo	*hash;
	uint8_t				supportedVersions;
} t_tlsCipherSuite;

typedef struct s_tlsSignatureAlgorithm {
	uint16_t			wireValue;
	const t_hashAlgo	*hash;
	const t_pkeyDef		*pkey;
	const char			*name;
	uint8_t				supportedVersions;
} t_tlsSigAlgo;

/* TLS version identifiers */
#define TLS_VERSION_1_0	0x0301
#define TLS_VERSION_1_1	0x0302
#define TLS_VERSION_1_2	0x0303
#define TLS_VERSION_1_3	0x0304

#define TLS_LEGACY_VERSION	0x0303	/* Used in record headers for TLS 1.2 compatibility */

/* TLS alert levels */
#define TLS_ALERT_LEVEL_WARNING	1
#define TLS_ALERT_LEVEL_FATAL	2

/* TLS alert descriptions */
#define TLS_ALERT_CLOSE_NOTIFY				0x00
#define TLS_ALERT_UNEXPECTED_MESSAGE		0x0A
#define TLS_ALERT_BAD_RECORD_MAC			0x14
#define TLS_ALERT_DECRYPTION_FAILED			0x15
#define TLS_ALERT_RECORD_OVERFLOW			0x16
#define TLS_ALERT_DECOMPRESSION_FAILURE		0x1E
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
#define TLS_ALERT_MISSING_EXTENSION			0x6D
#define TLS_ALERT_UNSUPPORTED_EXTENSION		0x6E
#define TLS_ALERT_CERTIFICATE_REQUIRED		0x70

/* TLS record content types */
#define TLS_RT_CHANGE_CIPHER_SPEC	0x14
#define TLS_RT_ALERT				0x15
#define TLS_RT_HANDSHAKE			0x16
#define TLS_RT_APPLICATION_DATA		0x17

/* TLS record header size */
#define TLS_RECORD_HEADER_SIZE		5

/* Maximum fragment length (2^14) */
#define TLS_MAX_FRAGMENT_LEN		16384

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
#define TLS_CIPHER_AES_128_GCM			0x1301
#define TLS_CIPHER_AES_256_GCM			0x1302
#define TLS_CIPHER_CHACHA20_POLY1305	0x1303

/* TLS signature algorithms */
#define TLS_SIG_RSA_PSS_RSAE_SHA256		0x0804
#define TLS_SIG_RSA_PSS_RSAE_SHA384		0x0805
#define TLS_SIG_RSA_PSS_RSAE_SHA512		0x0806
#define TLS_SIG_ECDSA_SHA1				0x0203
#define TLS_SIG_ECDSA_SECP256R1_SHA256	0x0403
#define TLS_SIG_ECDSA_SECP384R1_SHA384	0x0503
#define TLS_SIG_ECDSA_SECP521R1_SHA512	0x0603
#define TLS_SIG_RSA_PKCS1_SHA1			0x0201
#define TLS_SIG_RSA_PKCS1_SHA256		0x0401
#define TLS_SIG_RSA_PKCS1_SHA384		0x0501
#define TLS_SIG_RSA_PKCS1_SHA512		0x0601
#define TLS_SIG_DSA_SHA1				0x0202
#define TLS_SIG_DSA_SHA256				0x0402
#define TLS_SIG_DSA_SHA384				0x0502
#define TLS_SIG_DSA_SHA512				0x0602


size_t					getSupportedGroupsWire(uint16_t *out, size_t maxGroups, uint8_t tlsVersion);
int						selectGroup(const uint16_t *clientGroups, size_t clientCount, uint16_t *selectedWire, int *kexType, int *groupId);

size_t					getSupportedCipherSuitesWire(uint16_t *out, size_t maxSuites, uint8_t tlsVersion);
const t_tlsCipherSuite	*selectCipherSuite(const uint16_t *clientSuites, size_t clientCount);

size_t					getSupportedSignatureAlgorithmsWire(uint16_t *out, size_t maxAlgs, uint8_t tlsVersion);
const t_tlsSigAlgo		*selectSignatureAlgorithm(const uint16_t *clientAlgs, size_t clientCount);

extern const t_tlsGroup			g_supportedGroups[];
extern const t_tlsCipherSuite	g_supportedCipherSuites[];
extern const t_tlsSigAlgo		g_supportedSignatureAlgorithms[];
#endif /* TLS_CONSTANTS_H */
