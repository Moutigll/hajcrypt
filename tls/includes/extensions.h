#ifndef BTLS_EXTENSIONS_H
# define BTLS_EXTENSIONS_H

# include <stddef.h>
# include <stdint.h>

/**
 * @brief PSK (Pre-Shared Key) configuration
 *
 * This structure represents a pre-shared key identity and its binder.
 * Used for session resumption and 0-RTT in TLS 1.3.
 */
typedef struct s_tlsPsk
{
	uint8_t		*identity;				/* PSK identity */
	size_t		identityLen;
	uint8_t		*binder;				/* PSK binder (HMAC) */
	size_t		binderLen;
	uint32_t	obfuscatedTicketAge;	/* Ticket age for 0-RTT */
}	t_tlsPsk;

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) configuration
 *
 * This structure manages the list of application protocols supported by
 * the client and the protocol selected by the server.
 */
typedef struct s_tlsAlpnInternal
{
	char		**protocols;	/* List of protocols sent by client */
	size_t		numProtocols;
	char		*selected;		/* Protocol selected by server */
}	t_tlsAlpnInternal;

/**
 * @brief SNI (Server Name Indication) configuration
 *
 * This structure holds the server name requested by the client.
 */
typedef struct s_tlsSniInternal
{
	char		*hostname;	/* Server name requested by client */
}	t_tlsSniInternal;

/**
 * @brief OCSP Stapling configuration
 *
 * This structure manages Online Certificate Status Protocol (OCSP)
 * stapling, allowing the client to request a stapled OCSP response from
 * the server, and the server to provide that response.
 */
typedef struct s_tlsOcsp
{
	int		requested;	/* 1 if client requested OCSP */
	uint8_t	*response;	/* OCSP response (server sends) */
	size_t	responseLen;
	int		multiple;	/* 1 for status_request_v2 */
}	t_tlsOcsp;

/**
 * @brief OCSP Stapling v2 configuration (multiple responses)
 *
 * This structure extends OCSP stapling to support multiple certificate
 * status responses as defined in RFC 6961.
 */
typedef struct s_tlsOcspResponseEntry
{
	uint8_t		*response;
	size_t		responseLen;
}	t_tlsOcspResponseEntry;

typedef struct s_tlsOcspV2
{
	int						requested;
	t_tlsOcspResponseEntry	*responses;	/* Multiple OCSP responses */
	size_t					numResponses;
}	t_tlsOcspV2;

/**
 * @brief Signed Certificate Timestamp (SCT) configuration
 *
 * This structure handles Certificate Transparency (RFC 6962) signed
 * certificate timestamps for certificate transparency verification.
 */
typedef struct s_tlsSct
{
	uint8_t		*timestamp;	/* Raw SCT data */
	size_t		timestampLen;
	uint16_t	type;		/* 0: X.509 SCT, 1: OCSP SCT, 2: TLS SCT */
}	t_tlsSct;

typedef struct s_tlsSctList
{
	t_tlsSct	*scts;		/* List of SCTs */
	size_t		numScts;
}	t_tlsSctList;

/**
 * @brief Certificate compression configuration
 *
 * This structure manages certificate compression negotiation as defined
 * in RFC 8879. Supports algorithms like brotli, zlib, and zstd.
 */
typedef struct s_tlsCertCompressionInternal
{
	int			enabled;
	uint16_t	algorithms[8];		/* Supported algorithms */
	size_t		numAlgorithms;
	uint16_t	selected;			/* Selected by server */
	size_t		uncompressedLen;	/* Original size hint */
}	t_tlsCertCompressionInternal;

/**
 * @brief Record size limit configuration
 *
 * This structure manages the record size limit extension defined in
 * RFC 8449, allowing peers to negotiate a maximum TLS record size.
 */
typedef struct s_tlsRecordSizeLimitInternal
{
	int			enabled;
	uint16_t	limit;				/* Max record size (client proposes) */
}	t_tlsRecordSizeLimitInternal;

/**
 * @brief Key share entry
 *
 * This structure represents a single key share entry in the key_share
 * extension, containing a group identifier and the public key bytes.
 */
typedef struct s_tlsKeyShareEntry
{
	uint16_t	group;
	uint8_t		*key;	/* Public key bytes */
	size_t		keyLen;
}	t_tlsKeyShareEntry;

/**
 * @brief SRTP (Secure Real-time Transport Protocol) configuration
 *
 * This structure manages SRTP protection profiles as defined in RFC 5764.
 */
typedef struct s_tlsSrtp
{
	uint16_t	*profiles;		/* Supported SRTP protection profiles */
	size_t		numProfiles;
	uint16_t	selected;		/* Selected profile by server */
	uint8_t		*mki;			/* Master Key Identifier */
	size_t		mkiLen;
}	t_tlsSrtp;

/**
 * @brief Heartbeat configuration
 *
 * This structure manages the Heartbeat extension as defined in RFC 6520.
 * Used for DTLS and TLS heartbeat functionality.
 */
typedef struct s_tlsHeartbeat
{
	int			supported;		/* 1 if heartbeat is supported */
	uint8_t		mode;			/* 0: peer_allowed_to_send, 1: peer_not_allowed_to_send */
}	t_tlsHeartbeat;

/**
 * @brief Certificate type configuration
 *
 * This structure manages certificate type negotiation as defined in RFC 7250.
 * Supports X.509 and RawPublicKey certificate types.
 */
typedef struct s_tlsCertType
{
	uint8_t		*types;			/* Certificate types (X.509=0, RawPublicKey=1, etc.) */
	size_t		numTypes;
	uint8_t		selected;		/* Selected type by server */
}	t_tlsCertType;

/**
 * @brief Padding configuration
 *
 * This structure represents the padding extension (RFC 7685) used to
 * pad ClientHello messages to a desired length.
 */
typedef struct s_tlsPadding
{
	size_t		length;			/* Length of padding data */
}	t_tlsPadding;

/**
 * @brief Encrypt-then-MAC configuration (TLS 1.2)
 *
 * This structure manages the Encrypt-then-MAC extension as defined in RFC 7366.
 */
typedef struct s_tlsEncryptThenMac
{
	int			supported;		/* 1 if encrypt-then-MAC is supported */
}	t_tlsEncryptThenMac;

/**
 * @brief Extended Master Secret configuration (TLS 1.2)
 *
 * This structure manages the Extended Master Secret extension as defined in RFC 7627.
 */
typedef struct s_tlsExtendedMasterSecret
{
	int			supported;		/* 1 if extended master secret is supported */
}	t_tlsExtendedMasterSecret;

/**
 * @brief Renegotiation Info configuration (deprecated)
 *
 * This structure manages the renegotiation_info extension as defined in RFC 5746.
 */
typedef struct s_tlsRenegotiationInfo
{
	uint8_t		*renegotiatedConnection;	/* Renegotiated connection data */
	size_t		len;
}	t_tlsRenegotiationInfo;

/**
 * @brief Token Binding configuration
 *
 * This structure manages the Token Binding extension as defined in RFC 8472.
 */
typedef struct s_tlsTokenBinding
{
	uint8_t		*params;		/* Token binding parameters */
	size_t		paramsLen;
}	t_tlsTokenBinding;

/**
 * @brief Cached Info configuration
 *
 * This structure manages the Cached Info extension as defined in RFC 7924.
 * Allows clients to indicate cached certificate information.
 */
typedef struct s_tlsCachedInfo
{
	uint8_t		*cachedInfo;	/* Cached info data */
	size_t		cachedInfoLen;
}	t_tlsCachedInfo;

/**
 * @brief Ticket Pinning configuration
 *
 * This structure manages the Ticket Pinning extension as defined in RFC 8672.
 */
typedef struct s_tlsTicketPinning
{
	uint8_t		*ticket_pin;	/* Ticket pin data */
	size_t		pinLen;
}	t_tlsTicketPinning;

/**
 * @brief Supported EKT Ciphers configuration
 *
 * This structure manages the Supported EKT Ciphers extension as defined in RFC 8870.
 * Used for Encrypted Key Transport in session resumption.
 */
typedef struct s_tlsSupportedEktCiphers
{
	uint16_t	*ciphers;		/* Supported EKT ciphers */
	size_t		numCiphers;
}	t_tlsSupportedEktCiphers;

/**
 * @brief External ID Hash configuration
 *
 * This structure manages the External ID Hash extension as defined in RFC 8844.
 * Used for DTLS external session resumption.
 */
typedef struct s_tlsExternalIdHash
{
	uint8_t		*hash;			/* External ID hash */
	size_t		hashLen;
}	t_tlsExternalIdHash;

/**
 * @brief External Session ID configuration
 *
 * This structure manages the External Session ID extension as defined in RFC 8844.
 * Used for DTLS external session resumption.
 */
typedef struct s_tlsExternalSessionId
{
	uint8_t		*sessionId;	/* External session ID */
	size_t		idLen;
}	t_tlsExternalSessionId;

/**
 * @brief Ticket Request configuration
 *
 * This structure manages the Ticket Request extension as defined in RFC 9149.
 * Allows clients to request new session tickets.
 */
typedef struct s_tlsTicketRequest
{
	int			request;		/* 1 if ticket requested */
}	t_tlsTicketRequest;

/**
 * @brief Connection ID configuration (DTLS)
 *
 * This structure manages the Connection ID extension as defined in RFC 9146.
 * Used for DTLS connection migration.
 */
typedef struct s_tlsConnectionId
{
	uint8_t		*cid;			/* Connection ID */
	size_t		cidLen;
	uint8_t		*peerCid;		/* Peer's connection ID */
	size_t		peerCidLen;
}	t_tlsConnectionId;

/**
 * @brief RRC (Return Routability Check) configuration
 *
 * This structure manages the RRC extension as defined in RFC 9853.
 * Used for DTLS return routability checks.
 */
typedef struct s_tlsRrc
{
	uint8_t		*challenge;		/* RRC challenge */
	size_t		challengeLen;
}	t_tlsRrc;

/**
 * @brief TLS Flags configuration
 *
 * This structure manages the TLS Flags extension (draft-ietf-tls-tlsflags).
 */
typedef struct s_tlsTlsFlags
{
	uint64_t	flags;			/* Bitmask of TLS flags */
}	t_tlsTlsFlags;

/**
 * @brief ECH (Encrypted Client Hello) configuration
 *
 * This structure manages the Encrypted Client Hello extension as defined in RFC 9849.
 */
typedef struct s_tlsEch
{
	int			enabled;		/* 1 if ECH is enabled */
	uint8_t		*config_id;		/* ECH configuration ID */
	size_t		configIdLen;
	uint8_t		*enc;			/* Encrypted ECH data */
	size_t		encLen;
	uint8_t		*payload;		/* Decrypted payload */
	size_t		payloadLen;
}	t_tlsEch;

/**
 * @brief ECH Outer Extensions configuration
 *
 * This structure manages the ECH Outer Extensions extension as defined in RFC 9849.
 */
typedef struct s_tlsEchOuterExtensions
{
	uint16_t	*extensionTypes;	/* List of extension types for outer CH */
	size_t		numTypes;
}	t_tlsEchOuterExtensions;

/**
 * @brief QUIC Transport Parameters configuration
 *
 * This structure manages the QUIC Transport Parameters extension as defined in RFC 9001.
 */
typedef struct s_tlsQuicTransportParams
{
	uint8_t		*params;		/* QUIC transport parameters (as defined in RFC 9000) */
	size_t		paramsLen;
}	t_tlsQuicTransportParams;

/**
 * @brief Delegated Credential configuration
 *
 * This structure manages the Delegated Credential extension as defined in RFC 9345.
 * Allows servers to delegate signing authority to another key.
 */
typedef struct s_tlsDelegatedCredential
{
	uint8_t		*credential;	/* Delegated credential data */
	size_t		credentialLen;
	uint8_t		*signature;		/* Signature over the credential */
	size_t		signatureLen;
}	t_tlsDelegatedCredential;

/**
 * @brief Certificate Authorities configuration
 *
 * This structure manages the Certificate Authorities extension as defined in RFC 8446.
 * Lists acceptable CAs for client certificate selection.
 */
typedef struct s_tlsCertificateAuthorities
{
	uint8_t		**distinguishedNames;	/* List of CA DNs */
	size_t		*nameLens;
	size_t		numNames;
}	t_tlsCertificateAuthorities;

/**
 * @brief OID Filters configuration
 *
 * This structure manages the OID Filters extension as defined in RFC 8446.
 * Used for client certificate selection based on OIDs.
 */
typedef struct s_tlsOidFilters
{
	uint8_t		**oidValues;	/* OID values for filtering */
	size_t		*oidLengths;
	size_t		numOids;
}	t_tlsOidFilters;

/**
 * @brief Cookie configuration (DTLS)
 *
 * This structure manages the Cookie extension as defined in RFC 8446.
 * Used for DTLS to verify client reachability.
 */
typedef struct s_tlsCookie
{
	uint8_t		*cookie;		/* Cookie data */
	size_t		cookieLen;
}	t_tlsCookie;

/**
 * @brief Max Fragment Length configuration
 *
 * This structure manages the Max Fragment Length extension as defined in RFC 8449.
 */
typedef struct s_tlsMaxFragmentLength
{
	uint16_t	length;			/* Allowed values: 512, 1024, 2048, 4096 */
}	t_tlsMaxFragmentLength;

/**
 * @brief GREASE value detector
 *
 * Helper structure to detect and skip GREASE (RFC 8701) values.
 * GREASE values have the pattern 0x??0A?0A? (each byte ends with 0b1010).
 */
typedef struct s_tlsGrease
{
	int			is_grease;		/* 1 if value is GREASE */
	uint16_t	value;			/* The GREASE value detected */
}	t_tlsGrease;

/**
 * @brief Complete parsed extensions structure
 *
 * This structure holds all parsed TLS extensions from a ClientHello or
 * ServerHello message. It separates fields by category and includes both
 * TLS 1.3 specific features and features shared with TLS 1.2.
 */
typedef struct s_tlsParsedExtensions
{
	/* ===== Version negotiation (TLS 1.3) ===== */
	uint16_t	supportedVersions[4];	/* Versions supported by client */
	size_t		numSupportedVersions;
	uint16_t	negotiatedVersion;		/* Version selected by server */
	
	/* ===== Key exchange (TLS 1.3) ===== */
	uint16_t			*supportedGroups;		/* Groups supported by client */
	size_t				numSupportedGroups;
	t_tlsKeyShareEntry *keyShares;		/* Client's key shares */
	size_t				numKeyShares;
	uint16_t			selectedGroup;			/* Group selected by server */
	
	/* ===== Signature algorithms (shared) ===== */
	uint16_t	*signatureAlgs;			/* Signature algorithms */
	size_t		numSignatureAlgs;
	uint16_t	*signatureAlgsCert;		/* Signature algorithms for certs */
	size_t		numSignatureAlgsCert;
	
	/* ===== PSK / Session resumption (TLS 1.3) ===== */
	t_tlsPsk	*psks;					/* Pre-shared keys */
	size_t		numPsks;
	uint8_t		pskModes;				/* PSK key exchange modes */
	int			pskKe;					/* 1 if psk_ke mode supported */
	int			pskDheKe;				/* 1 if psk_dhe_ke mode supported */
	
	/* ===== Session resumption (TLS 1.2) ===== */
	uint8_t		*sessionTicket;			/* Session ticket (RFC 5077) */
	size_t		sessionTicketLen;
	
	/* ===== Identification (shared) ===== */
	t_tlsSniInternal			sni;				/* Server Name Indication */
	t_tlsCertificateAuthorities certAuthorities;	/* Certificate authorities (RFC 8446) */
	t_tlsOidFilters				oidFilters;			/* OID filters (RFC 8446) */
	
	/* ===== Application protocols (shared) ===== */
	t_tlsAlpnInternal	alpn;			/* ALPN */
	
	/* ===== Performance (shared) ===== */
	t_tlsMaxFragmentLength			maxFragmentLength;	/* Max fragment length */
	t_tlsRecordSizeLimitInternal	recordSizeLimit;
	t_tlsCertCompressionInternal	certCompression;
	
	/* ===== Security features (shared) ===== */
	uint8_t						*ecPointFormats;		/* EC point formats */
	size_t						numEcPointFormats;	
	t_tlsOcsp					ocsp;					/* OCSP stapling */
	t_tlsOcspV2					ocspV2;					/* OCSP stapling v2 */
	t_tlsSctList				sct;					/* Signed Certificate Timestamp */
	t_tlsHeartbeat				heartbeat;				/* Heartbeat extension */
	t_tlsCertType				clientCertType;			/* Client certificate type */
	t_tlsCertType				serverCertType;			/* Server certificate type */
	t_tlsPadding				padding;				/* Padding extension */
	t_tlsTokenBinding			tokenBinding;			/* Token binding */
	t_tlsCachedInfo				cachedInfo;				/* Cached info */
	t_tlsTicketPinning			ticketPinning;			/* Ticket pinning */
	t_tlsSupportedEktCiphers	supportedEktCiphers;	/* Supported EKT ciphers */
	t_tlsExternalIdHash			externalIdHash;			/* External ID hash */
	t_tlsExternalSessionId		externalSessionId;		/* External session ID */
	t_tlsTicketRequest			ticketRequest;			/* Ticket request */
	int	postHandshakeAuth;	/* Post-handshake authentication */
	
	/* ===== Security features (TLS 1.2 only) ===== */
	t_tlsEncryptThenMac			encryptThenMac;			/* Encrypt-then-MAC */
	t_tlsExtendedMasterSecret	extendedMasterSecret;	/* Extended master secret */
	t_tlsRenegotiationInfo		renegotiationInfo;		/* Renegotiation info */
	
	/* ===== DTLS extensions ===== */
	t_tlsCookie			cookie;				/* DTLS cookie */
	t_tlsConnectionId	connectionId;		/* Connection ID */
	t_tlsRrc			rrc;				/* RRC extension */
	t_tlsTlsFlags		tlsFlags;			/* TLS flags */
	
	/* ===== Modern features (TLS 1.3) ===== */
	uint8_t						*earlyData;				/* Early data content (client) */
	size_t						earlyDataLen;
	t_tlsQuicTransportParams	quicParams;				/* QUIC transport parameters */
	t_tlsDelegatedCredential	delegatedCredential;	/* Delegated credential */
	t_tlsEch					ech;					/* Encrypted Client Hello */
	t_tlsEchOuterExtensions		echOuterExtensions;		/* ECH outer extensions */
	
	/* ===== SRTP (shared) ===== */
	t_tlsSrtp			srtp;				/* SRTP protection profiles */
	
}	t_tlsParsedExtensions;

typedef struct s_tlsExtension {
	uint16_t	type;				/* Extension type */
	const char	*name;				/* Extension name (for debugging) */
	int			(*parser)(const uint8_t *data, size_t dataLen, t_tlsParsedExtensions *out, int isServer);	/* Parser function for this extension */
	uint8_t		supportedVersions;	/* Bitmask of supported TLS versions (1.2=0x01, 1.3=0x02) */
}	t_tlsExtension;

/**
 * @brief Parse all extensions from a ClientHello or ServerHello
 *
 * This function parses all extensions present in a TLS handshake message.
 * It reads the extension type and data, then dispatches to the appropriate
 * parser for each known extension type. Unknown extensions are stored
 * in the rawExtensions array for debugging or forwarding.
 *
 * @param data			Raw extension data (the extensions block from the message)
 * @param dataLen		Length of the extension data
 * @param out			Output structure for parsed extensions (must be initialised)
 * @param isServerHello	1 if parsing ServerHello, 0 if parsing ClientHello
 * @return				1 on success, 0 on error
 */
int		tlsParseExtensions(const uint8_t *data, size_t dataLen, t_tlsParsedExtensions *out, int isServerHello);

/**
 * @brief Free all dynamically allocated memory in a t_tlsParsedExtensions structure
 *
 * This function frees all dynamically allocated buffers within the t_tlsParsedExtensions
 * structure, such as supported groups, key shares, PSKs, ALPN protocols, OCSP responses, etc.
 * It also resets the structure to zero after freeing.
 *
 * @param ext	Structure to free (must be initialised)
 */
void tlsFreeParsedExtensions(t_tlsParsedExtensions *ext);

/**
 * @brief Print the contents of parsed extensions for debugging
 *
 * This function prints the contents of a t_tlsParsedExtensions structure in a
 * human-readable format. It is useful for debugging and understanding what
 * extensions were received and how they were parsed.
 *
 * @param ext	Parsed extensions to print
 */
void tlsPrintParsedExtensions(const t_tlsParsedExtensions *ext);


#endif /* BTLS_EXTENSIONS_H */
