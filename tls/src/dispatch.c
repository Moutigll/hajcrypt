#include "../../includes/asymmetric/kex.h"
#include "../../includes/hash/sha.h" /* IWYU pragma: keep */
#include "../../includes/asymmetric/rsa.h"
#include "../../includes/asymmetric/dsa.h"
#include "../../includes/asymmetric/ecdsa.h"
#include "../../includes/cipher/aes.h"
#include "../../includes/cipher/des.h"
#include "../../includes/cipher/des3.h"

#include "../includes/constants.h"

static inline int isVersionSupported(uint8_t supportedVersions, uint8_t tlsVersion)
{
	return (supportedVersions & tlsVersion) != 0;
}

/**
 * @brief Supported groups table
 */
const t_tlsGroup g_supportedGroups[] = {
	/* ECDHE (Best for performance and widely supported) */
	{ TLS_NAMED_GROUP_X25519,		KEX_TYPE_ECDH, ECDH_GROUP_X25519,		"x25519",		TLS_VERS_1_3 },
	{ TLS_NAMED_GROUP_SECP256R1,	KEX_TYPE_ECDH, ECDH_GROUP_SECP256R1, 	"secp256r1",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_NAMED_GROUP_SECP384R1,	KEX_TYPE_ECDH, ECDH_GROUP_SECP384R1, 	"secp384r1",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_NAMED_GROUP_SECP521R1,	KEX_TYPE_ECDH, ECDH_GROUP_SECP521R1, 	"secp521r1",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_NAMED_GROUP_X448,			KEX_TYPE_ECDH, ECDH_GROUP_X448,			"x448",			TLS_VERS_1_3 },
	/* FFDHE (Good fallback, but less efficient) */
	{ TLS_NAMED_GROUP_FFDHE2048,	KEX_TYPE_FFDHE, FFDHE_GROUP_2048,		"ffdhe2048",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_NAMED_GROUP_FFDHE3072,	KEX_TYPE_FFDHE, FFDHE_GROUP_3072,		"ffdhe3072",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_NAMED_GROUP_FFDHE4096,	KEX_TYPE_FFDHE, FFDHE_GROUP_4096,		"ffdhe4096",	TLS_VERS_1_3 },
	{ TLS_NAMED_GROUP_FFDHE6144,	KEX_TYPE_FFDHE, FFDHE_GROUP_6144,		"ffdhe6144",	TLS_VERS_1_3 },
	{ TLS_NAMED_GROUP_FFDHE8192,	KEX_TYPE_FFDHE, FFDHE_GROUP_8192,		"ffdhe8192",	TLS_VERS_1_3 },
};

static const t_aeadCipher g_aes128GcmCipher = {
	.keySize = 16,
	.ivSize = 12,
	.tagLen = 16
};

static const t_aeadCipher g_aes256GcmCipher = {
	.keySize = 32,
	.ivSize = 12,
	.tagLen = 16
};

static const t_aeadCipher g_chacha20Poly1305Cipher = {
	.keySize = 32,
	.ivSize = 12,
	.tagLen = 16
};

/**
 * @brief Supported cipher suites table
 *
 * Ordered by priority: TLS 1.3 first, then TLS 1.2 with ECDHE (strongest),
 * then DHE_RSA, then RSA (static, no PFS), and finally obsolete suites (disabled).
 *
 * Note: For TLS 1.2, kex and pkey fields are used to determine the key exchange
 * and authentication algorithms. For TLS 1.3, these fields are set to KEX_TYPE_NONE
 * and NULL respectively as they are negotiated via extensions.
 */
const t_tlsCipherSuite g_supportedCipherSuites[] = {
	/* ========================================================================
	 * TLS 1.3 (RFC 8446) - KEX and auth negotiated via extensions
	 * ======================================================================== */
	{
		TLS_CIPHER_AES_128_GCM,
		"TLS_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_NONE,
		NULL,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		TLS_VERS_1_3
	},
	{
		TLS_CIPHER_AES_256_GCM,
		"TLS_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_NONE,
		NULL,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		TLS_VERS_1_3
	},
	{
		TLS_CIPHER_CHACHA20_POLY1305,
		"TLS_CHACHA20_POLY1305_SHA256",
		BTLS_CIPHER_CHACHA20_POLY1305,
		BTLS_RECORD_AEAD,
		KEX_TYPE_NONE,
		NULL,
		{ .aeadCipher = &g_chacha20Poly1305Cipher },
		&g_sha256Hash,
		TLS_VERS_1_3
	},

	/* ========================================================================
	 * TLS 1.2 - ECDHE + ECDSA (Strongest, PFS)
	 * ======================================================================== */
	/* ECDHE_ECDSA with AES-GCM (AEAD) */
	{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* ECDHE_ECDSA with ChaCha20-Poly1305 (AEAD) */
	{
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		BTLS_CIPHER_CHACHA20_POLY1305,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .aeadCipher = &g_chacha20Poly1305Cipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},

	/* ECDHE_ECDSA with CBC + HMAC-SHA256/384 */
	{
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* ========================================================================
	 * TLS 1.2 - ECDHE + RSA (Strong, PFS)
	 * ======================================================================== */
	/* ECDHE_RSA with AES-GCM (AEAD) */
	{
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* ECDHE_RSA with ChaCha20-Poly1305 (AEAD) */
	{
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		BTLS_CIPHER_CHACHA20_POLY1305,
		BTLS_RECORD_AEAD,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_chacha20Poly1305Cipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},

	/* ECDHE_RSA with CBC + HMAC-SHA256/384 */
	{
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* ========================================================================
	 * TLS 1.2 - DHE + RSA (PFS, fallback for older clients)
	 * ======================================================================== */
	/* DHE_RSA with AES-GCM (AEAD) */
	{
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* DHE_RSA with ChaCha20-Poly1305 (AEAD) */
	{
		TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		BTLS_CIPHER_CHACHA20_POLY1305,
		BTLS_RECORD_AEAD,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_chacha20Poly1305Cipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},

	/* DHE_RSA with CBC + HMAC-SHA256 */
	{
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},

	/* ========================================================================
	 * TLS 1.2 - DHE + DSA (Obsolete, rarely used)
	 * ======================================================================== */
	/* DHE_DSA with AES-GCM (AEAD) - disabled by default */
	{
		TLS_DHE_DSA_WITH_AES_128_GCM_SHA256,
		"TLS_DHE_DSA_WITH_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_FFDHE,
		&g_dsaPkeyDef,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		0  /* Disabled: DSA is obsolete */
	},
	{
		TLS_DHE_DSA_WITH_AES_256_GCM_SHA384,
		"TLS_DHE_DSA_WITH_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_FFDHE,
		&g_dsaPkeyDef,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		0  /* Disabled: DSA is obsolete */
	},

	/* DHE_DSA with CBC + HMAC-SHA256 */
	{
		TLS_DHE_DSA_WITH_AES_128_CBC_SHA256,
		"TLS_DHE_DSA_WITH_AES_128_CBC_SHA256",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_dsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha256Hash,
		0  /* Disabled: DSA is obsolete */
	},
	{
		TLS_DHE_DSA_WITH_AES_256_CBC_SHA256,
		"TLS_DHE_DSA_WITH_AES_256_CBC_SHA256",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_dsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha256Hash,
		0  /* Disabled: DSA is obsolete */
	},

	/* ========================================================================
	 * TLS 1.2 - RSA (Static, No PFS)
	 * ======================================================================== */
	/* RSA with AES-GCM (AEAD) */
	{
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		BTLS_CIPHER_AES_128_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes128GcmCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		BTLS_CIPHER_AES_256_GCM,
		BTLS_RECORD_AEAD,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .aeadCipher = &g_aes256GcmCipher },
		&g_sha384Hash,
		TLS_VERS_1_2
	},

	/* RSA with CBC + HMAC-SHA256 */
	{
		TLS_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},
	{
		TLS_RSA_WITH_AES_256_CBC_SHA256,
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha256Hash,
		TLS_VERS_1_2
	},

	/* ========================================================================
	 * TLS 1.2 - RSA with 3DES (Weak, disabled)
	 * ======================================================================== */
	{
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		BTLS_CIPHER_3DES_EDE_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_des3CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: 3DES is weak */
	},
	{
		TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		BTLS_CIPHER_3DES_EDE_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_des3CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: 3DES is weak */
	},

	/* ========================================================================
	 * TLS 1.2 - RSA with DES (Obsolete, disabled)
	 * ======================================================================== */
	{
		TLS_RSA_WITH_DES_CBC_SHA,
		"TLS_RSA_WITH_DES_CBC_SHA",
		BTLS_CIPHER_DES_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_desCbcCipher },
		&g_sha1Hash,
		0  /* Disabled: DES is obsolete */
	},
	{
		TLS_DHE_RSA_WITH_DES_CBC_SHA,
		"TLS_DHE_RSA_WITH_DES_CBC_SHA",
		BTLS_CIPHER_DES_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_desCbcCipher },
		&g_sha1Hash,
		0  /* Disabled: DES is obsolete */
	},

	/* ========================================================================
	 * TLS 1.2 - SHA-1 based suites (All disabled)
	 * ======================================================================== */
	/* RSA + SHA-1 */
	{
		TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},
	{
		TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_NONE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},

	/* DHE_RSA + SHA-1 */
	{
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},
	{
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_FFDHE,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},

	/* ECDHE_ECDSA + SHA-1 */
	{
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},
	{
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_ecdsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},

	/* ECDHE_RSA + SHA-1 */
	{
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		BTLS_CIPHER_AES_128_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes128CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},
	{
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		BTLS_CIPHER_AES_256_CBC,
		BTLS_RECORD_CBC_HMAC,
		KEX_TYPE_ECDH,
		&g_rsaPkeyDef,
		{ .cipher = &g_aes256CbcCipher },
		&g_sha1Hash,
		0  /* Disabled: SHA-1 is broken */
	},

	/* ========================================================================
	 * Terminator
	 * ======================================================================== */
	{ 0, NULL, 0, 0, 0, NULL, NULL, 0 }
};

/**
 * @brief Supported signature algorithms table
 */
const t_tlsSigAlgo g_supportedSignatureAlgorithms[] = {
	{ TLS_SIG_ECDSA_SHA1,				&g_sha1Hash,	&g_ecdsaPkeyDef,	"ecdsa_sha1",				0}, /* Deprecated */
	{ TLS_SIG_ECDSA_SECP256R1_SHA256,	&g_sha256Hash,	&g_ecdsaPkeyDef,	"ecdsa_secp256r1_sha256",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_SIG_ECDSA_SECP384R1_SHA384,	&g_sha384Hash,	&g_ecdsaPkeyDef,	"ecdsa_secp384r1_sha384",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	{ TLS_SIG_ECDSA_SECP521R1_SHA512,	&g_sha512Hash,	&g_ecdsaPkeyDef,	"ecdsa_secp521r1_sha512",	TLS_VERS_1_3 | TLS_VERS_1_2 },
	/* RSA-PSS (TLS 1.3) */
	{ TLS_SIG_RSA_PSS_PSS_SHA256,		&g_sha256Hash,	&g_rsaPkeyDef, 		"rsa_pss_pss_sha256",		TLS_VERS_1_3 },
	{ TLS_SIG_RSA_PSS_PSS_SHA384,		&g_sha384Hash,	&g_rsaPkeyDef, 		"rsa_pss_pss_sha384",		TLS_VERS_1_3 },
	{ TLS_SIG_RSA_PSS_PSS_SHA512,		&g_sha512Hash,	&g_rsaPkeyDef, 		"rsa_pss_pss_sha512",		TLS_VERS_1_3 },
	{ TLS_SIG_RSA_PSS_RSAE_SHA256,		&g_sha256Hash,	&g_rsaPkeyDef, 		"rsa_pss_rsae_sha256",		TLS_VERS_1_3 },
	{ TLS_SIG_RSA_PSS_RSAE_SHA384,		&g_sha384Hash,	&g_rsaPkeyDef,		"rsa_pss_rsae_sha384",		TLS_VERS_1_3 },
	{ TLS_SIG_RSA_PSS_RSAE_SHA512,		&g_sha512Hash,	&g_rsaPkeyDef,		"rsa_pss_rsae_sha512",		TLS_VERS_1_3 },
	/* ECDSA (TLS 1.3 and 1.2) */
	/* RSA PKCS#1 v1.5 (TLS 1.2 only, not recommended) */
	{ TLS_SIG_RSA_PKCS1_SHA1,			&g_sha1Hash,	&g_rsaPkeyDef,		"rsa_pkcs1_sha1",			0 }, /* Deprecated */
	{ TLS_SIG_RSA_PKCS1_SHA256,		&g_sha256Hash,	&g_rsaPkeyDef,		"rsa_pkcs1_sha256",			TLS_VERS_1_2 },
	{ TLS_SIG_RSA_PKCS1_SHA384,		&g_sha384Hash,	&g_rsaPkeyDef,		"rsa_pkcs1_sha384",			TLS_VERS_1_2 },
	{ TLS_SIG_RSA_PKCS1_SHA512,		&g_sha512Hash,	&g_rsaPkeyDef,		"rsa_pkcs1_sha512",			TLS_VERS_1_2 },
	/* DSA (TLS 1.2 only, not recommended) */
	{ TLS_SIG_DSA_SHA1,			&g_sha1Hash,	&g_dsaPkeyDef,		"dsa_sha1",						0 }, /* Deprecated */
	{ TLS_SIG_DSA_SHA256,			&g_sha256Hash,	&g_dsaPkeyDef,		"dsa_sha256",					TLS_VERS_1_2 },
	{ TLS_SIG_DSA_SHA384,			&g_sha384Hash,	&g_dsaPkeyDef,		"dsa_sha384",					TLS_VERS_1_2 },
	{ TLS_SIG_DSA_SHA512,			&g_sha512Hash,	&g_dsaPkeyDef,		"dsa_sha512",					TLS_VERS_1_2 },
};

#define NUM_SUPPORTED_GROUPS		(sizeof(g_supportedGroups) / sizeof(t_tlsGroup))
#define NUM_SUPPORTED_CIPHER_SUITES	(sizeof(g_supportedCipherSuites) / sizeof(t_tlsCipherSuite))
#define NUM_SUPPORTED_SIG_ALGS		(sizeof(g_supportedSignatureAlgorithms) / sizeof(t_tlsSigAlgo))

size_t getSupportedGroupsWire(uint16_t *out, size_t maxGroups, uint8_t tlsVersion)
{
	size_t count = 0;
	for (size_t i = 0; i < NUM_SUPPORTED_GROUPS && count < maxGroups; i++) {
		if (isVersionSupported(g_supportedGroups[i].supportedVersions, tlsVersion)) {
			out[count++] = g_supportedGroups[i].wireValue;
		}
	}
	return (count);
}

int negotiateGroup(const uint16_t *clientGroups, size_t clientCount, uint16_t *selectedWire, int *kexType, int *groupId)
{
	for (size_t i = 0; i < clientCount; i++) {
		for (size_t j = 0; j < NUM_SUPPORTED_GROUPS; j++) {
			if (clientGroups[i] == g_supportedGroups[j].wireValue) {
				*selectedWire = g_supportedGroups[j].wireValue;
				*kexType = g_supportedGroups[j].kexType;
				*groupId = g_supportedGroups[j].groupId;
				return (1);
			}
		}
	}
	return (0);
}


size_t getSupportedCipherSuitesWire(uint16_t *out, size_t maxSuites, uint8_t tlsVersion)
{
	size_t count = 0;
	for (size_t i = 0; i < NUM_SUPPORTED_CIPHER_SUITES && count < maxSuites; i++) {
		if (isVersionSupported(g_supportedCipherSuites[i].supportedVersions, tlsVersion)) {
			out[count++] = g_supportedCipherSuites[i].wireValue;
		}
	}
	return (count);
}

const t_tlsCipherSuite *negotiateCipherSuite(const uint16_t *clientSuites, size_t clientCount)
{
	for (size_t i = 0; i < clientCount; i++) {
		for (size_t j = 0; j < NUM_SUPPORTED_CIPHER_SUITES; j++) {
			if (clientSuites[i] == g_supportedCipherSuites[j].wireValue)
				return (&g_supportedCipherSuites[j]);
		}
	}
	return (NULL);
}


size_t getSupportedSignatureAlgorithmsWire(uint16_t *out, size_t maxAlgs, uint8_t tlsVersion)
{
	size_t count = 0;
	for (size_t i = 0; i < NUM_SUPPORTED_SIG_ALGS && count < maxAlgs; i++) {
		if (isVersionSupported(g_supportedSignatureAlgorithms[i].supportedVersions, tlsVersion)) {
			out[count++] = g_supportedSignatureAlgorithms[i].wireValue;
		}
	}
	return (count);
}

const t_tlsSigAlgo *negotiateSignatureAlgorithm(const uint16_t *clientAlgs, size_t clientCount)
{
	for (size_t i = 0; i < clientCount; i++) {
		for (size_t j = 0; j < NUM_SUPPORTED_SIG_ALGS; j++) {
			if (clientAlgs[i] == g_supportedSignatureAlgorithms[j].wireValue)
				return (&g_supportedSignatureAlgorithms[j]);
		}
	}
	return (NULL);
}

const t_tlsGroup *getGroup(uint16_t wireValue)
{
	for (size_t i = 0; i < NUM_SUPPORTED_GROUPS; i++)
	{
		if (wireValue == g_supportedGroups[i].wireValue)
			return (&g_supportedGroups[i]);
	}
	return (NULL);
}

const t_tlsCipherSuite *getCipherSuite(uint16_t wireValue)
{
	for (size_t i = 0; i < NUM_SUPPORTED_CIPHER_SUITES; i++)
	{
		if (wireValue == g_supportedCipherSuites[i].wireValue)
			return (&g_supportedCipherSuites[i]);
	}
	return (NULL);
}

const t_tlsSigAlgo *getSigAlgo(uint16_t wireValue)
{
	for (size_t i = 0; i < NUM_SUPPORTED_SIG_ALGS; i++)
	{
		if (wireValue == g_supportedSignatureAlgorithms[i].wireValue)
			return (&g_supportedSignatureAlgorithms[i]);
	}
	return (NULL);
}
