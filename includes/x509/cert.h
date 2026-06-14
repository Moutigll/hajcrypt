#ifndef HAJCRYPT_CERT_H
# define HAJCRYPT_CERT_H

# include <time.h>

#include "../asymmetric/pkey.h"

/**
 * @brief X.509 certificate structure
 *
 * This structure holds a parsed X.509 certificate in DER format with
 * extracted fields for easy access. The DER buffer is owned by the
 * structure and must be freed with x509CertFree().
 */
typedef struct s_x509Cert
{
	uint8_t		*der;			/* Raw DER certificate */
	size_t		derLen;			/* Length of DER data */
	
	/* Principal fields (optional, for validation) */
	uint8_t		*issuer;		/* Distinguished Name of issuer */
	size_t		issuerLen;
	uint8_t		*subject;		/* Distinguished Name of subject */
	size_t		subjectLen;
	uint8_t		*serial;		/* Serial number */
	size_t		serialLen;
	
	/* Validity period */
	time_t		notBefore;		/* Unix timestamp (start) */
	time_t		notAfter;		/* Unix timestamp (end) */
	
	/* Public key */
	t_pkey		pubKey;			/* Public key structure */
	uint8_t		*pubKeyRaw;		/* Raw public key bytes (from BIT STRING) */
	size_t		pubKeyRawLen;
	
	/* Signature */
	uint8_t		*signature;		/* Certificate signature */
	size_t		sigLen;
	int			sigAlgo;		/* OID of signature algorithm */
	
	/* Extensions */
	uint8_t		**extensions;	/* Extension data buffers */
	size_t		*extLens;		/* Extension data lengths */
	size_t		extCount;		/* Number of extensions */
	
	/* Fingerprints */
	uint8_t		sha256Fingerprint[32];	/* SHA-256 fingerprint */
	uint8_t		sha384Fingerprint[48];	/* SHA-384 fingerprint */
}	t_x509Cert;

/**
 * @brief Distinguished Name attribute structure
 *
 * This structure represents a single attribute in a Distinguished Name (DN),
 * consisting of an OID and a string value. Used for parsing and printing DNs.
 */
typedef struct s_dnAttr {
	const t_algoId	*oid;
	char			*value;
} t_dnAttr;

/**
 * @brief Certificate chain structure
 *
 * This structure holds a chain of X.509 certificates. The first element
 * (index 0) is the leaf/end-entity certificate, followed by intermediate
 * certificates, and optionally the root CA certificate.
 */
typedef struct s_certChain
{
	t_x509Cert	**certs;		/* Array of certificate pointers (leaf first) */
	size_t		count;			/* Number of certificates in chain */
}	t_certChain;

/**
 * @brief Gets the short name for a known OID
 *
 * This function returns a human-readable short name for a known OID used
 * in DNs (e.g., "CN" for commonName). For unknown OIDs, it returns NULL.
 *
 * @param oid		OID data buffer
 * @param oidLen	Length of OID data
 * @return			Short name string, or NULL if unknown OID
 */
const char *getDnAttrName(const uint8_t *oid, size_t oidLen);

/**
 * @brief Parses an X.509 certificate from DER format
 *
 * This function parses a DER-encoded X.509 certificate and extracts
 * all relevant fields (issuer, subject, validity, public key, signature,
 * extensions). The returned structure owns all allocated memory.
 *
 * @param der		DER-encoded certificate data
 * @param derLen	Length of DER data
 * @return			Pointer to parsed certificate, or NULL on error
 */
t_x509Cert	*x509CertParse(const uint8_t *der, size_t derLen);

/**
 * @brief Creates a new X.509 certificate
 *
 * This function creates a new X.509 certificate with the specified fields.
 * The certificate is unsigned and does not contain extensions. The returned
 * structure owns all allocated memory.
 *
 * @param pkey			Public key to include in the certificate
 * @param subject		Subject Distinguished Name (string format)
 * @param issuer		Issuer Distinguished Name (string format)
 * @param notBefore		Validity start time (Unix timestamp)
 * @param notAfter		Validity end time (Unix timestamp)
 * @param serial		Serial number (binary data)
 * @param serialLen		Length of serial number data
 * @return				Pointer to new certificate, or NULL on error
 */
t_x509Cert *x509CertNew(const t_pkey	*pkey,
						const char		*subject,	const char	*issuer,
						time_t			notBefore,	time_t		notAfter,
						uint8_t			*serial,	size_t		serialLen);

/**
 * @brief Frees an X.509 certificate
 *
 * This function frees all memory associated with a parsed certificate,
 * including the DER buffer, all extracted fields, and extensions.
 *
 * @param cert		Certificate to free
 */
void		x509CertFree(t_x509Cert *cert);

/**
 * @brief Creates a new empty certificate chain
 *
 * This function allocates and initialises an empty certificate chain
 * structure. The chain must be freed with certChainFree().
 *
 * @return			Pointer to new certificate chain, or NULL on error
 */
t_certChain	*certChainNew(void);

/**
 * @brief Adds a parsed certificate to a certificate chain
 *
 * This function appends a certificate to the chain. The chain takes
 * ownership of the certificate pointer.
 *
 * @param chain		Certificate chain
 * @param cert		Certificate to add (chain takes ownership)
 * @return			1 on success, 0 on error
 */
int			certChainAdd(t_certChain *chain, t_x509Cert *cert);

/**
 * @brief Adds a DER-encoded certificate to a certificate chain
 *
 * This function parses a DER-encoded certificate and adds it to the chain.
 * The chain takes ownership of the parsed certificate.
 *
 * @param chain		Certificate chain
 * @param der		DER-encoded certificate data
 * @param derLen	Length of DER data
 * @return			1 on success, 0 on error
 */
int			certChainAddDER(t_certChain *chain, const uint8_t *der, size_t derLen);

/**
 * @brief Frees a certificate chain and all its certificates
 *
 * This function frees all certificates in the chain and the chain
 * structure itself.
 *
 * @param chain		Certificate chain to free
 */
void		certChainFree(t_certChain *chain);

#endif /* HAJCRYPT_CERT_H */
