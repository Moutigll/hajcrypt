#ifndef BTLS_H
# define BTLS_H

# include "../../includes/x509/cert.h"

# include "keySchedule.h"
# include "record.h"
# include "hello.h"
# include "io.h"

/**
 * @brief TLS version negotiation preferences
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
 * @brief TLS handshake state machine states
 *
 * This enumeration tracks the progress of a TLS handshake through its various
 * stages. States are separated by protocol version (TLS 1.3 vs TLS 1.2) and
 * role (client vs server). The state machine transitions as messages are
 * sent and received during the handshake.
 */
typedef enum e_tlsHandshakeState
{
	/* Initial states */
	TLS_HS_STATE_IDLE = 0,
	TLS_HS_STATE_SERVER_WAIT_CLIENT_HELLO,		/* Waiting for ClientHello */
	TLS_HS_STATE_CLIENT_SEND_HELLO,				/* Want to send ClientHello */

	/* TLS 1.3 - Server side */
	TLS_HS_STATE_13_SERVER_SEND_FLIGHT,			/* Server wants to send ServerHello+EncryptedExtensions+Cert+CertVerify+Finished */
	TLS_HS_STATE_13_SERVER_WAIT_CLIENT_FINISHED,	/* Server waiting to receive Client Finished */

	/* TLS 1.3 - Client side */
	TLS_HS_STATE_13_CLIENT_WAIT_FLIGHT,			/* Waiting for ServerHello+EncryptedExtensions+Cert+CertVerify+Finished */
	TLS_HS_STATE_13_CLIENT_SEND_FINISHED,		/* Client ready to send Client Finished */

	/* TLS 1.2 - Server side */
	TLS_HS_STATE_12_SERVER_SEND_CLEAR_FLIGHT,	/* Server wants to send ServerHello+Certificate+ServerHelloDone (cleartext) */
	TLS_HS_STATE_12_SERVER_WAIT_CLIENT_FLIGHT,	/* Server waiting to receive ClientKeyExchange+ChangeCipherSpec+Finished */
	TLS_HS_STATE_12_SERVER_SEND_CCS_FINISHED,	/* Server ready to send ChangeCipherSpec+Finished (encrypted) */

	/* TLS 1.2 - Client side */
	TLS_HS_STATE_12_CLIENT_WAIT_CLEAR_FLIGHT,	/* Client waiting to receive ServerHello+Certificate+ServerHelloDone (cleartext) */
	TLS_HS_STATE_12_CLIENT_SEND_CCS_FINISHED,	/* Client ready to send ClientKeyExchange+ChangeCipherSpec+Finished */
	TLS_HS_STATE_12_CLIENT_WAIT_CCS_FINISHED,	/* Client waiting to receive ChangeCipherSpec+Finished (encrypted) */

	/* Final states */
	TLS_HS_STATE_13_CONNECTED,					/* Handshake completed */
	TLS_HS_STATE_12_CONNECTED,					/* Handshake completed */
	TLS_HS_STATE_ERROR							/* Handshake failed, can be send at any time */
}	t_tlsHandshakeState;

/**
 * @brief TLS configuration (shared across all connections)
 *
 * All parameters and credentials are stored here. The application
 * initialises a single instance with tlsConfigInit(), optionally loads
 * a certificate and private key with tlsConfigLoadCertKey(), then
 * passes a pointer to this config when calling tlsAccept() or tlsConnect().
 * Fields can be modified directly by the caller after initialisation.
 */
typedef struct s_tlsConfig
{
	int					middleboxCompat;	/* 1 if operating in middlebox compatibility mode */
	t_tlsVersionPref	versionPref;		/* Preferred TLS version */
	int					isBlocking;			/* 1 for blocking mode, 0 for non-blocking */
	int					sendGrease;			/* 1 to include GREASE values when possible */
	int					verifyPeer;			/* 1 to verify peer's certificate */
	int					allowSelfSigned;	/* 1 to allow self-signed certificates */
	int					verifyDepth;		/* Maximum verification depth */
	t_certChain			*certChain;			/* Certificate chain (leaf first) – NULL if none */
	t_pkey				*privateKey;		/* Private key – NULL if none */
}	t_tlsConfig;

/**
 * @brief TLS handshake context structure
 *
 * This structure holds all state for a TLS handshake including the current
 * state machine position, protocol version, cipher suite, transcript hash,
 * key schedule secrets, record protection contexts, key exchange material,
 * and the peer's certificate chain.
 */
typedef struct s_tlsHandshakeCtx
{
	/* State */
	t_tlsHandshakeState	state;				/* Current handshake state */
	int					isClient;			/* 1 for client, 0 for server */
	uint16_t			version;			/* Negotiated TLS version */
	int					flightBuffered;		/* 1 if flight is buffered */

	/* Hello messages */
	t_tlsHello			peerHello;			/* Parsed peer Hello message */
	uint8_t				peerHelloMsg[TLS_MAX_FRAGMENT_LEN];	/* Raw peer Hello message */
	size_t				peerHelloMsgLen;	/* Length of raw peer Hello message */

	/* Transcript hash */
	t_hash				transcriptHash;		/* Hash algorithm for transcript */
	/* We must force 16-byte alignment for the hash context to avoid unaligned access and therefore potential crashes on some architectures. */
	void				*transcriptHashCtx[HASH_MAX_CTX_SIZE] __attribute__((aligned(16)));	/* Hash context for transcript */
	uint8_t				clientRandom[32];	/* Client random (from ClientHello) */
	uint8_t				serverRandom[32];	/* Server random (from ServerHello) */

	/* Negotiation */
	uint16_t			cipherSuite;		/* Negotiated cipher suite */

	/* Key schedule (TLS 1.3) */
	t_tls13Secrets		secrets;			/* Derived secrets */

	/* Record layer */
	t_tlsRecordCtx		handshakeSendCtx;	/* Sending handshake traffic */
	t_tlsRecordCtx		handshakeRecvCtx;	/* Receiving handshake traffic */
	t_tlsRecordCtx		appSendCtx;			/* Sending application data */
	t_tlsRecordCtx		appRecvCtx;			/* Receiving application data */

	/* Key exchange */
	t_kexCtx			*keyExchangeCtx;	/* Key exchange context */
	uint8_t				sharedSecret[64];	/* Computed shared secret */
	size_t				sharedSecretLen;	/* Length of shared secret */

	/* Peer certificate (received) */
	t_certChain			*peerCertChain;		/* Peer certificate chain (leaf first) */
}	t_tlsHandshakeCtx;

/**
 * @brief TLS connection context (user‑facing API)
 *
 * This structure holds everything needed for a TLS connection:
 * a pointer to the shared configuration, I/O context, handshake state,
 * and connection status.  No manual initialisation is required before
 * calling tlsAccept() or tlsConnect() – they will set up the context
 * automatically.
 */
typedef struct s_tlsCtx
{
	const t_tlsConfig	*config;	/* Connection parameters (read‑only) */
	t_tlsIoctx			io;			/* I/O context */
	t_tlsHandshakeCtx	handshake;	/* Handshake state */
	int					isConnected;/* 1 if handshake complete */
	int					isServer;	/* 1 for server, 0 for client */
	uint8_t				appDataBuf[TLS_MAX_FRAGMENT_LEN];	/* Application data buffer */
	size_t				appDataLen;	/* Length of application data */
	int					lastError;	/* Last error code */
	char				*errorMsg;	/* Human‑readable error message */
}	t_tlsCtx;

/* Success */
# define TLS_SUCCESS				0

/* General errors */
# define TLS_ERR_INTERNAL			-1		/* Internal error (memory, etc.) */
# define TLS_ERR_HANDSHAKE			-2		/* Handshake failed */
# define TLS_ERR_PROTOCOL			-3		/* Protocol error */
# define TLS_ERR_WOULD_BLOCK		-4		/* Non‑blocking mode would block */

/* Authentication errors */
# define TLS_ERR_CERT				-10		/* Certificate error */
# define TLS_ERR_CERT_EXPIRED		-11		/* Certificate expired */
# define TLS_ERR_CERT_REVOKED		-12		/* Certificate revoked */
# define TLS_ERR_CERT_UNKNOWN_CA	-13		/* Unknown CA */
# define TLS_ERR_HOSTNAME_MISMATCH	-14		/* Hostname doesn't match certificate */
# define TLS_ERR_SELF_SIGNED		-15		/* Self‑signed certificate (not allowed) */

/* Crypto errors */
# define TLS_ERR_DECRYPT			-20		/* Decryption failed */
# define TLS_ERR_MAC				-21		/* MAC verification failed */
# define TLS_ERR_SIGNATURE			-22		/* Signature verification failed */

/* Network errors */
# define TLS_ERR_EOF				-30		/* Connection closed by peer */
# define TLS_ERR_TIMEOUT			-31		/* Operation timed out */
# define TLS_ERR_IO					-40		/* I/O error */
# define TLS_ERR_WANT_READ			-41		/* Non‑blocking: need read */
# define TLS_ERR_WANT_WRITE			-42		/* Non‑blocking: need write */

/**
 * @brief Initialises a TLS configuration with default values
 *
 * All fields are set to safe defaults. The caller can then modify
 * fields directly and optionally call tlsConfigLoadCertKey() to
 * load a certificate / private key.
 *
 * @param cfg		Configuration to initialise
 * @return			1 on success, 0 on error
 */
int		tlsConfigInit(t_tlsConfig *cfg);

/**
 * @brief Frees resources owned by a TLS configuration
 *
 * Frees the certificate chain and private key if they were loaded.
 * The configuration itself is not freed (caller owns the memory).
 *
 * @param cfg		Configuration to clean up
 */
void	tlsConfigFree(t_tlsConfig *cfg);

/**
 * @brief Loads a certificate chain and private key into the configuration
 *
 * The certificate file can be PEM (single or concatenated) or DER.
 * The private key must be PEM format. Any previously loaded
 * certificate/key is freed before loading the new one.
 *
 * @param cfg			Configuration to fill
 * @param certFile		Path to certificate chain file (PEM or DER)
 * @param keyFile		Path to private key file (PEM)
 * @param keyPassword	Password for the private key file (if encrypted)
 * @return				1 on success, 0 on error
 */
int		tlsConfigLoadCertKey(t_tlsConfig *cfg, const char *certFile, const char *keyFile, const char *keyPassword);

/**
 * @brief Perform TLS handshake as server
 *
 * Creates a new TLS connection context attached to the given configuration
 * and socket, then processes the handshake up to the point where the socket
 * would block. The caller must provide a pointer to an uninitialised
 * t_tlsCtx (zeroed or freshly allocated); it will be initialised internally.
 * When the handshake completes, the context is ready for application data.
 *
 * In non‑blocking mode, this function may return TLS_ERR_WANT_READ
 * or TLS_ERR_WANT_WRITE to indicate that the caller should wait for
 * the socket to become readable or writable and then call tlsAccept()
 * again to resume the handshake (the same context pointer must be reused).
 *
 * @param ctx		Pointer to an uninitialised t_tlsCtx
 * @param cfg		Shared configuration (read‑only)
 * @param socket	Connected socket file descriptor
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsAccept(t_tlsCtx *ctx, const t_tlsConfig *cfg, int socket);

/**
 * @brief Perform TLS handshake as client
 *
 * Creates a new TLS connection context attached to the given configuration
 * and socket, then processes the handshake up to the point where the socket
 * would block. The caller must provide a pointer to an uninitialised
 * t_tlsCtx (zeroed or freshly allocated); it will be initialised internally.
 * When the handshake completes, the context is ready for application data.
 *
 * In non‑blocking mode, this function may return TLS_ERR_WANT_READ
 * or TLS_ERR_WANT_WRITE to indicate that the caller should wait for
 * the socket to become readable or writable and then call tlsConnect()
 * again to resume the handshake (the same context pointer must be reused).
 *
 * @param ctx		Pointer to an uninitialised t_tlsCtx
 * @param cfg		Shared configuration (read‑only)
 * @param socket	Connected socket file descriptor
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsConnect(t_tlsCtx *ctx, const t_tlsConfig *cfg, int socket);

/**
 * @brief Check if TLS connection is established
 *
 * This function returns whether the TLS handshake has completed
 * successfully and the connection is ready for application data.
 *
 * @param ctx		TLS context
 * @return			1 if connected, 0 otherwise
 */
int		tlsIsConnected(const t_tlsCtx *ctx);

/**
 * @brief Read application data from TLS connection
 *
 * This function reads decrypted application data from the TLS connection.
 * It may return fewer bytes than requested. In non‑blocking mode, it may
 * return TLS_ERR_WANT_READ if no data is available and the socket would
 * block, or TLS_ERR_WANT_WRITE if a write is needed to continue.
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
 * In non‑blocking mode, it may return TLS_ERR_WANT_WRITE if the socket
 * would block, or TLS_ERR_WANT_READ if a read is needed to continue.
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
 * The context is NOT freed by this function; call tlsFreeConnection()
 * afterwards to release all resources.
 *
 * @param ctx		TLS context
 * @return			TLS_SUCCESS on success, error code otherwise
 */
int		tlsShutdown(t_tlsCtx *ctx);

/**
 * @brief Frees a per‑connection TLS context and closes the socket
 *
 * Releases all resources associated with the connection, including
 * handshake state, internal buffers, and the underlying socket.
 * The configuration is not touched. After calling this function
 * the context becomes invalid.
 *
 * @param ctx		Connection context to free
 */
void	tlsFreeConnection(t_tlsCtx *ctx);

/**
 * @brief Sets an error on the TLS context
 *
 * This function records an error code and human‑readable message on the
 * TLS context for later retrieval.
 *
 * @param ctx		TLS context
 * @param errCode	Error code (TLS_ERR_*)
 * @param errMsg	Human‑readable error message
 */
void	tlsSetError(t_tlsCtx *ctx, int errCode, const char *errMsg);

/**
 * @brief Handle an incoming TLS alert
 *
 * This function processes a TLS alert message, logging it and updating
 * the connection state. It returns -1 for fatal alerts, 0 for closure,
 * and 1 otherwise.
 *
 * @param ctx		TLS context
 * @param data		Alert data (two bytes: level, description)
 * @param dataLen	Length of data (must be >= 2)
 * @return			-1 on fatal, 0 on close_notify, 1 on warning
 */
int		tlsHandleAlert(t_tlsCtx *ctx, const uint8_t *data, size_t dataLen);

#endif /* BTLS_H */
