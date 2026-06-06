#ifndef BTLS_H
# define BTLS_H

# include "handshake.h"
# include "io.h"

/**
 * @brief TLS version negotiation
 *
 * This enumeration controls which TLS versions are supported and which
 * is preferred when multiple versions are enabled. TLS 1.3 is the default
 * and recommended version. Fallback to TLS 1.2 is available for backward
 * compatibility with legacy servers or clients.
 */
typedef enum e_tlsVersionPref
{
	TLS_VERSION_PREF_TLS13_ONLY = 0,		/* Only TLS 1.3 (default) */
	TLS_VERSION_PREF_TLS13_WITH_FALLBACK,	/* TLS 1.3, fallback to 1.2 */
	TLS_VERSION_PREF_TLS12_ONLY,			/* Only TLS 1.2 */
	TLS_VERSION_PREF_TLS13_AND_12,			/* Both TLS 1.3 and 1.2, prefer 1.3 */
}	t_tlsVersionPref;

/**
 * @brief Supported ALPN protocols (Application-Layer Protocol Negotiation)
 *
 * This structure manages the list of application protocols supported by
 * the client (e.g., "h2", "http/1.1", "websocket"). The server selects
 * one of these protocols during the handshake. Defined in RFC 7301.
 */
typedef struct s_tlsAlpn
{
	const char		**protocols;	/* Array of protocol names (e.g., "h2", "http/1.1") */
	size_t			numProtocols;	/* Number of protocols in array */
	const char		*selected;		/* Selected protocol by server (client reads this) */
}	t_tlsAlpn;

/**
 * @brief Server Name Indication (SNI) configuration
 *
 * SNI allows the client to specify which virtual host it wants to connect
 * to, enabling a single IP address to host multiple TLS certificates.
 * Defined in RFC 6066.
 */
typedef struct s_tlsSni
{
	char		*hostname;		/* Server name (e.g., "www.example.com") */
	int			sendEmpty;		/* 1 to send empty SNI (disables SNI) */
}	t_tlsSni;

/**
 * @brief Maximum fragment length negotiation
 *
 * This extension allows peers to negotiate a smaller maximum fragment
 * length than the default 2^14 bytes (16384). Useful for constrained
 * environments such as embedded devices or low-memory systems.
 * Defined in RFC 6066.
 */
typedef struct s_tlsMaxFragment
{
	int			enabled;		/* 1 to negotiate, 0 to use default */
	uint16_t	length;			/* Desired max fragment length (512, 1024, 2048, 4096) */
}	t_tlsMaxFragment;

/**
 * @brief OCSP Stapling (Certificate Status Request)
 *
 * OCSP stapling allows the client to request that the server sends an
 * OCSP response stapled directly in the handshake, avoiding an extra
 * OCSP request to the CA. This improves privacy and performance.
 * Defined in RFC 6066 (status_request).
 */
typedef struct s_tlsOcspStapling
{
	int		enabled;		/* 1 to enable OCSP stapling */
	uint8_t	*response;		/* OCSP response (server fills, client reads) */
	size_t	responseLen;	/* Length of OCSP response */
}	t_tlsOcspStapling;

/**
 * @brief Certificate compression (RFC 8879)
 *
 * Certificate compression reduces the size of the certificate chain
 * during the handshake, which is particularly beneficial for large
 * certificate chains. Supported algorithms include brotli, zlib, and zstd.
 */
typedef struct s_tlsCertCompression
{
	int			enabled;		/* 1 to enable certificate compression */
	uint16_t	algorithm;		/* 0 = brotli, 1 = zlib, 2 = zstd (RFC 8879) */
	size_t		uncompressedLen;/* Original length (server uses to allocate) */
}	t_tlsCertCompression;

/**
 * @brief Record size limit (RFC 8449)
 *
 * This extension allows peers to negotiate a limit on the size of
 * individual TLS records. It can help with buffering constraints or
 * to reduce latency on high-bandwidth connections.
 */
typedef struct s_tlsRecordSizeLimit
{
	int			enabled;		/* 1 to negotiate record size limit */
	uint16_t	limit;			/* Max record size (default 16384) */
}	t_tlsRecordSizeLimit;

/**
 * @brief Post-Handshake Authentication
 *
 * Post-handshake authentication allows the server to request client
 * authentication after the initial handshake has completed. This is
 * useful for applications that need to authenticate the client only
 * for certain resources. Defined in RFC 8446 (post_handshake_auth).
 */
typedef struct s_tlsPostHandshakeAuth
{
	int			enabled;		/* 1 to enable post-handshake auth */
	int			requested;		/* Server sets this when requesting client cert */
}	t_tlsPostHandshakeAuth;

/**
 * @brief QUIC Transport Parameters (RFC 9001)
 *
 * This structure carries QUIC transport parameters inside the TLS handshake
 * for authenticated negotiation when using TLS over QUIC (HTTP/3).
 */
typedef struct s_tlsQuicParams
{
	int			enabled;		/* 1 if using QUIC (not TCP) */
	uint8_t		*params;		/* QUIC transport parameters (encoded) */
	size_t		paramsLen;		/* Length of QUIC parameters */
}	t_tlsQuicParams;

/**
 * @brief Delegated Credentials (RFC 9345)
 *
 * Delegated credentials allow servers to delegate signing authority to
 * a separate key, which is useful for CDNs and load balancers that need
 * to terminate TLS without access to the private certificate key.
 */
typedef struct s_tlsDelegatedCred
{
	int			enabled;		/* 1 to enable delegated credentials */
	uint8_t		*credential;	/* Delegated credential (server sends) */
	size_t		credLen;		/* Length of delegated credential */
}	t_tlsDelegatedCred;

/**
 * @brief Session Ticket (RFC 5077)
 *
 * Session tickets enable stateless session resumption. The server
 * generates a ticket containing session state, encrypted with a server
 * secret. The client stores the ticket and presents it later to resume
 * the session without a full handshake.
 */
typedef struct s_tlsSessionTicket
{
	int			enabled;		/* 1 to enable session tickets */
	uint8_t		*ticket;		/* Session ticket data (server generates) */
	size_t		ticketLen;		/* Length of session ticket */
	uint32_t	lifetime;		/* Ticket lifetime in seconds */
}	t_tlsSessionTicket;

/**
 * @brief Early Data (0-RTT) configuration
 *
 * Early data (0-RTT) allows sending application data before the handshake
 * completes, reducing latency for repeat connections. This requires a
 * previously established PSK (session ticket). Defined in RFC 8446 (early_data).
 */
typedef struct s_tlsEarlyData
{
	int			enabled;		/* 1 to enable 0-RTT */
	int			maxEarlyData;	/* Maximum amount of early data (server) */
	uint8_t		*data;			/* Early data buffer (client) */
	size_t		dataLen;		/* Length of early data */
}	t_tlsEarlyData;

/**
 * @brief Key Update configuration
 *
 * This structure controls automatic key update behavior. Periodic key
 * updates improve forward secrecy and limit the amount of data encrypted
 * under a single key. Defined in RFC 8446 (key_update).
 */
typedef struct s_tlsKeyUpdate
{
	int			autoUpdate;		/* 1 to auto-update keys periodically */
	uint64_t	updateInterval;	/* Update after this many records (0 = never) */
}	t_tlsKeyUpdate;

/**
 * @brief Certificate verification options
 *
 * This structure configures peer certificate validation behavior,
 * including whether to verify peer certificates, hostname matching,
 * CA trust store locations, and verification depth.
 */
typedef struct s_tlsCertVerify
{
	int			verifyPeer;			/* 1 to verify peer's certificate */
	int			verifyHostname;		/* 1 to verify hostname matches certificate */
	int			allowSelfSigned;	/* 1 to allow self-signed certificates */
	char		*caFile;			/* Path to CA bundle file (PEM) */
	char		*caPath;			/* Path to CA directory (PEM) */
	int			depth;				/* Maximum verification depth */
}	t_tlsCertVerify;

/**
 * @brief TLS connection parameters (user-configurable)
 *
 * This structure groups all configurable parameters for a TLS connection.
 * Default values are set by tlsInit() and can be overridden by the user
 * before calling tlsConnect() or tlsAccept().
 */
typedef struct s_tlsParams
{
	t_tlsVersionPref		versionPref;		/* Preferred TLS version */
	int						isClient;			/* 1 for client, 0 for server */
	int						socket;				/* Connected socket */
	int						isBlocking;			/* 1 for blocking mode, 0 for non-blocking */
	t_tlsAlpn				alpn;				/* ALPN negotiation */
	t_tlsSni				sni;				/* SNI for virtual hosting */
	t_tlsQuicParams			quic;				/* QUIC transport parameters */
	int						isDtls;				/* 1 for DTLS (UDP), 0 for TLS (TCP) */
	t_tlsMaxFragment		maxFragment;		/* Maximum fragment length */
	t_tlsRecordSizeLimit	recordSizeLimit;	/* Record size limit */
	t_tlsCertVerify			certVerify;			/* Certificate verification options */
	t_tlsOcspStapling		ocspStapling;		/* OCSP stapling */
	t_tlsCertCompression	certCompression;	/* Certificate compression */
	t_tlsSessionTicket		sessionTicket;		/* Session tickets */
	t_tlsEarlyData			earlyData;			/* 0-RTT early data */
	t_tlsKeyUpdate			keyUpdate;			/* Key update configuration */
	t_tlsPostHandshakeAuth	postHandshakeAuth;	/* Post-handshake authentication */
	t_tlsDelegatedCred		delegatedCred;		/* Delegated credentials */
	int						handshakeTimeout;	/* Handshake timeout (0 = none) */
	int						readTimeout;		/* Read timeout (0 = none) */
	int						writeTimeout;		/* Write timeout (0 = none) */
}	t_tlsParams;

/**
 * @brief TLS connection context (user-facing API)
 *
 * This structure holds everything needed for a TLS connection:
 * configuration parameters, handshake state, I/O buffers, and
 * connection status. It is the main context object used by the
 * application when interacting with the TLS library.
 */
typedef struct s_tlsCtx
{
	t_tlsParams			params;			/* Configuration (set by user) */
	t_tlsIoctx			io;				/* I/O context */
	t_tlsHandshakeCtx	handshake;		/* Handshake state */
	int					isConnected;	/* 1 if handshake complete */
	int					isServer;		/* 1 for server, 0 for client */
	uint8_t				appDataBuf[TLS_MAX_FRAGMENT_LEN];	/* Application data buffer */
	size_t				appDataLen;		/* Length of application data */
	int					lastError;		/* Last error code */
	char				errorMsg[256];	/* Human-readable error message */
}	t_tlsCtx;



/* --------------- Error Codes --------------- */

/* Success */
# define TLS_SUCCESS				0

/* General errors */
# define TLS_ERR_INTERNAL			-1		/* Internal error (memory, etc.) */
# define TLS_ERR_HANDSHAKE			-2		/* Handshake failed */
# define TLS_ERR_PROTOCOL			-3		/* Protocol error */
# define TLS_ERR_WOULD_BLOCK		-4		/* Non-blocking mode would block */

/* Authentication errors */
# define TLS_ERR_CERT				-10		/* Certificate error */
# define TLS_ERR_CERT_EXPIRED		-11		/* Certificate expired */
# define TLS_ERR_CERT_REVOKED		-12		/* Certificate revoked */
# define TLS_ERR_CERT_UNKNOWN_CA	-13		/* Unknown CA */
# define TLS_ERR_HOSTNAME_MISMATCH	-14		/* Hostname doesn't match certificate */
# define TLS_ERR_SELF_SIGNED		-15		/* Self-signed certificate (not allowed) */

/* Crypto errors */
# define TLS_ERR_DECRYPT			-20		/* Decryption failed */
# define TLS_ERR_MAC				-21		/* MAC verification failed */
# define TLS_ERR_SIGNATURE			-22		/* Signature verification failed */

/* Network errors */
# define TLS_ERR_EOF				-30		/* Connection closed by peer */
# define TLS_ERR_TIMEOUT			-31		/* Operation timed out */



/* --------------- Public API --------------- */

/**
 * @brief Initialize TLS context with default parameters
 *
 * This function initialises a TLS context with default parameters based
 * on the role (client or server) and the provided connected socket.
 * The default parameters include TLS 1.3 only, blocking mode, and no
 * custom extensions. The context must be freed with tlsFree() when no
 * longer needed.
 *
 * @param ctx		TLS context (must be allocated by caller)
 * @param isClient	1 for client mode, 0 for server mode
 * @param socket	Connected socket file descriptor
 * @return			1 on success, 0 on error
 */
int		tlsInit(t_tlsCtx *ctx, int isClient, int socket);

/**
 * @brief Initialize TLS context with custom parameters
 *
 * This function allows the caller to set custom parameters before
 * initiating the handshake. It copies the provided parameters into
 * the context. Call this function instead of tlsInit() when custom
 * configuration is needed.
 *
 * @param ctx		TLS context (must be allocated by caller)
 * @param params	Custom parameters (copied internally)
 * @return			1 on success, 0 on error
 */
int		tlsInitWithParams(t_tlsCtx *ctx, const t_tlsParams *params);

/**
 * @brief Free TLS context and close connection
 *
 * This function frees all resources associated with the TLS context,
 * securely zeroes sensitive material, and closes the underlying socket.
 * After calling tlsFree(), the context must not be used again.
 *
 * @param ctx		TLS context
 */
void	tlsFree(t_tlsCtx *ctx);

/**
 * @brief Get last error code
 *
 * This function returns the last error code recorded by the TLS context.
 * It is useful for determining the cause of a failed operation.
 *
 * @param ctx		TLS context
 * @return			Error code (TLS_ERR_*)
 */
int		tlsLastError(t_tlsCtx *ctx);

/**
 * @brief Get human-readable error message
 *
 * This function returns a human-readable string describing the last
 * error that occurred. The pointer remains valid until the next
 * operation that modifies the context.
 *
 * @param ctx		TLS context
 * @return			Pointer to error string (do not free)
 */
const char	*tlsErrorString(t_tlsCtx *ctx);

/**
 * @brief Set SNI hostname (client side)
 *
 * This function sets the Server Name Indication (SNI) hostname for client
 * mode. The hostname indicates which virtual server the client wants to
 * connect to, allowing the server to select the correct certificate.
 *
 * @param ctx		TLS context
 * @param hostname	Server name (e.g., "www.example.com")
 * @return			1 on success, 0 on error
 */
int		tlsSetSni(t_tlsCtx *ctx, const char *hostname);

/**
 * @brief Set ALPN protocols (client side)
 *
 * This function sets the list of supported application protocols for
 * ALPN negotiation. The protocols array should be NULL-terminated.
 * The server will select one of these protocols during the handshake.
 *
 * @param ctx		TLS context
 * @param protocols	Array of protocol names (e.g., {"h2", "http/1.1", NULL})
 * @return			1 on success, 0 on error
 */
int		tlsSetAlpn(t_tlsCtx *ctx, const char **protocols);

/**
 * @brief Get negotiated ALPN protocol
 *
 * This function returns the ALPN protocol selected by the server during
 * the handshake. If no protocol was negotiated, it returns NULL.
 *
 * @param ctx		TLS context
 * @return			Selected protocol name, or NULL if not negotiated
 */
const char	*tlsGetAlpn(t_tlsCtx *ctx);

/**
 * @brief Set OCSP stapling (client side)
 *
 * This function enables or disables OCSP stapling (Certificate Status
 * Request) for client mode. When enabled, the client requests an OCSP
 * response from the server during the handshake.
 *
 * @param ctx		TLS context
 * @param enabled	1 to request OCSP stapling, 0 to disable
 * @return			1 on success, 0 on error
 */
int		tlsSetOcspStapling(t_tlsCtx *ctx, int enabled);

/**
 * @brief Get OCSP response (server side, after handshake)
 *
 * This function retrieves the OCSP response that the client requested
 * via OCSP stapling. It is used by the server to send a stapled OCSP
 * response to the client.
 *
 * @param ctx		TLS context
 * @param response	Output pointer to OCSP response data
 * @param len		Output length of OCSP response
 * @return			1 if OCSP response is available, 0 otherwise
 */
int		tlsGetOcspResponse(t_tlsCtx *ctx, uint8_t **response, size_t *len);

/**
 * @brief Set certificate verification options
 *
 * This function configures certificate verification behaviour, including
 * whether to verify the peer's certificate and the CA trust store paths.
 *
 * @param ctx			TLS context
 * @param verifyPeer	1 to verify peer's certificate
 * @param caFile		Path to CA bundle file (PEM), or NULL
 * @param caPath		Path to CA directory, or NULL
 * @return				1 on success, 0 on error
 */
int		tlsSetVerify(t_tlsCtx *ctx, int verifyPeer, const char *caFile, const char *caPath);

/**
 * @brief Set hostname for certificate verification (client side)
 *
 * This function sets the expected hostname for certificate verification
 * on the client side. The certificate's CN or SAN must match this hostname.
 *
 * @param ctx		TLS context
 * @param hostname	Expected hostname (must match certificate)
 * @return			1 on success, 0 on error
 */
int		tlsSetVerifyHostname(t_tlsCtx *ctx, const char *hostname);

/**
 * @brief Perform TLS handshake as client
 *
 * This function initiates the TLS handshake from the client side.
 * It sends a ClientHello and processes server responses until the
 * handshake completes or an error occurs.
 *
 * @param ctx		TLS context
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsConnect(t_tlsCtx *ctx);

/**
 * @brief Perform TLS handshake as server
 *
 * This function performs the TLS handshake from the server side.
 * It waits for a ClientHello from the client and responds with the
 * appropriate handshake messages (ServerHello, Certificate, etc.).
 *
 * @param ctx		TLS context
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsAccept(t_tlsCtx *ctx);

/**
 * @brief Read application data from TLS connection
 *
 * This function reads decrypted application data from the TLS connection.
 * It may return fewer bytes than requested. In non-blocking mode, it may
 * return TLS_ERR_WOULD_BLOCK if no data is available.
 *
 * @param ctx		TLS context
 * @param buf		Output buffer
 * @param len		Maximum bytes to read
 * @return			Number of bytes read, 0 on EOF, negative on error
 */
ssize_t	tlsRead(t_tlsCtx *ctx, uint8_t *buf, size_t len);

/**
 * @brief Write application data to TLS connection
 *
 * This function encrypts and writes application data to the TLS connection.
 * It may write fewer bytes than requested if the record size limit is reached.
 *
 * @param ctx		TLS context
 * @param buf		Data to write
 * @param len		Number of bytes to write
 * @return			Number of bytes written, negative on error
 */
ssize_t	tlsWrite(t_tlsCtx *ctx, const uint8_t *buf, size_t len);

/**
 * @brief Shutdown TLS connection (send close_notify)
 *
 * This function sends a close_notify alert to the peer and then closes
 * the underlying socket. This is the proper way to shut down a TLS
 * connection, ensuring both peers know the connection is ending.
 *
 * @param ctx		TLS context
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsShutdown(t_tlsCtx *ctx);

/**
 * @brief Check if TLS connection is established
 *
 * This function returns whether the TLS handshake has completed
 * successfully and the connection is ready for application data.
 *
 * @param ctx		TLS context
 * @return			1 if connected, 0 otherwise
 */
int		tlsIsConnected(t_tlsCtx *ctx);

/**
 * @brief Get peer certificate chain (DER format)
 *
 * This function retrieves the peer's certificate chain after a successful
 * handshake. The chain is returned as a DER-encoded buffer.
 *
 * @param ctx		TLS context
 * @param certChain	Output pointer to certificate chain data
 * @param len		Output length of certificate chain
 * @return			1 if certificate is available, 0 otherwise
 */
int		tlsGetPeerCertificate(t_tlsCtx *ctx, uint8_t **certChain, size_t *len);

/**
 * @brief Export keying material (RFC 5705)
 *
 * This function allows applications to derive additional keys from the
 * TLS session using the exporter interface. It is useful for protocols
 * that need additional keys (e.g., WebRTC, DTLS-SRTP).
 *
 * @param ctx			TLS context
 * @param label			Exporter label
 * @param context		Context value (may be NULL)
 * @param contextLen	Length of context
 * @param output		Output buffer
 * @param outputLen		Desired length of output
 * @return				1 on success, 0 on error
 */
int		tlsExportKeyingMaterial(t_tlsCtx *ctx, const char *label, const uint8_t *context, size_t contextLen, uint8_t *output, size_t outputLen);

#endif /* BTLS_H */
