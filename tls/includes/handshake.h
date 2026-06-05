#ifndef BTLS_HANDSHAKE_H
# define BTLS_HANDSHAKE_H

# include "../../includes/asymmetric/pkey.h"
# include "../../includes/asymmetric/kex.h"
# include "../../includes/hash/hash.h"

# include "keySchedule.h"
# include "record.h"

/**
 * @brief TLS handshake message types (RFC 8446)
 *
 * These values represent the message type field in the handshake message
 * header. The message_hash type (0xFE) is used internally for transcript
 * hash operations and is not sent over the wire.
 */
typedef enum e_tlsHandshakeType
{
	TLS_HT_CLIENT_HELLO			= 0x01,
	TLS_HT_SERVER_HELLO			= 0x02,
	TLS_HT_NEW_SESSION_TICKET	= 0x04,
	TLS_HT_ENCRYPTED_EXTENSIONS	= 0x08,
	TLS_HT_CERTIFICATE			= 0x0B,
	TLS_HT_CERTIFICATE_REQUEST	= 0x0D,
	TLS_HT_CERTIFICATE_VERIFY	= 0x0F,
	TLS_HT_FINISHED				= 0x14,
	TLS_HT_KEY_UPDATE			= 0x18,
	TLS_HT_MESSAGE_HASH			= 0xFE
}	t_tlsHandshakeType;

/**
 * @brief TLS handshake message header
 *
 * This structure represents the 4-byte header of a TLS handshake message.
 * The length field is 24 bits and can represent values up to 16,777,215 bytes.
 * The actual message body follows the header and its size is given by the
 * length field. Messages larger than the maximum fragment size (16,384 bytes)
 * must be fragmented across multiple TLS records.
 *
 * struct {
 *	 uint8 msg_type;
 *	 uint24 length;
 *	 uint8 body[length];
 * } HandshakeMessage;
 */
typedef struct s_tlsHandshakeHeader
{
	uint8_t		msgType;
	uint32_t	length;	/* 24 bits, stored in lower 24 bits */
}	t_tlsHandshakeHeader;

/**
 * @brief Handshake state machine states
 *
 * This enumeration tracks the progress of the TLS 1.3 handshake through
 * its various stages. The state transitions are driven by message exchange
 * and key schedule operations. After the Finished messages are exchanged,
 * the handshake enters the CONNECTED state where application data can flow.
 */
typedef enum e_tlsHandshakeState
{
	TLS_HS_STATE_IDLE = 0,
	TLS_HS_STATE_CLIENT_HELLO_SENT,
	TLS_HS_STATE_SERVER_HELLO_RECVD,
	TLS_HS_STATE_ENCRYPTED_EXTENSIONS_RECVD,
	TLS_HS_STATE_CERTIFICATE_RECVD,
	TLS_HS_STATE_CERTIFICATE_VERIFY_RECVD,
	TLS_HS_STATE_FINISHED_RECVD,
	TLS_HS_STATE_FINISHED_SENT,
	TLS_HS_STATE_CONNECTED,
	TLS_HS_STATE_ERROR
}	t_tlsHandshakeState;

/**
 * @brief TLS handshake context
 *
 * This structure holds all state for a TLS handshake including the current
 * state machine position, the transcript hash of all handshake messages,
 * the negotiated cipher suite, and the derived key schedule secrets.
 * It also maintains separate record protection contexts for handshake
 * and application traffic in both send and receive directions.
 */
typedef struct s_tlsHandshakeCtx
{
	t_tlsHandshakeState	state;
	int					isClient;				/* 1 for client, 0 for server */
	t_hashAlgo			transcriptHash;			/* Hash algorithm for transcript (SHA-256 or SHA-384) */
	uint8_t				transcript[64];			/* Transcript hash value (32 bytes for SHA-256, 48 bytes for SHA-384) */
	t_tlsCipherType		cipherSuite;			/* Negotiated cipher suite (AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305) */
	t_tls13Secrets		secrets;				/* Key schedule secrets (early, handshake, master) */
	t_tlsRecordCtx		handshakeRecvCtx;		/* Record context for receiving handshake messages */
	t_tlsRecordCtx		handshakeSendCtx;		/* Record context for sending handshake messages */
	t_tlsRecordCtx		appRecvCtx;				/* Record context for receiving application messages */
	t_tlsRecordCtx		appSendCtx;				/* Record context for sending application messages */
	t_kexCtx			*keyExchangeCtx;		/* Key exchange context (e.g., t_ecdhCtx for ECDHE) */
	uint8_t				*certChain;				/* Certificate chain (DER-encoded, concatenated) */
	size_t				certChainLen;			/* Length of certificate chain */
	t_pkey				*privateKey;			/* t_rsaKey or t_dsaKey */
}	t_tlsHandshakeCtx;

/**
 * @brief Initialize handshake context
 *
 * This function initializes the handshake context with the specified role
 * (client or server) and hash algorithm. It zeros all sensitive buffers,
 * sets up the transcript hash, and prepares the key schedule structure
 * for HKDF operations. Must be called before any handshake processing.
 *
 * @param ctx		Handshake context to initialize
 * @param isClient	1 for client mode, 0 for server mode
 * @param hash		Hash algorithm for transcript (SHA-256 or SHA-384)
 * @return			1 on success, 0 on error
 */
int	tlsHandshakeInit(t_tlsHandshakeCtx *ctx, int isClient, const t_hashAlgo *hash);

/**
 * @brief Free handshake context (zero sensitive data)
 *
 * This function securely zeros all sensitive material in the handshake
 * context including the transcript hash, key schedule secrets, record
 * protection keys, and any key exchange or certificate data. After
 * freeing, the context should not be reused without reinitialization.
 *
 * @param ctx	Handshake context to free
 */
void	tlsHandshakeFree(t_tlsHandshakeCtx *ctx);

/**
 * @brief Process incoming handshake message
 *
 * This function processes a received handshake message, updates the
 * transcript hash, transitions the state machine, and generates any
 * necessary response messages. It is the core of the handshake state
 * machine and handles all message types including ClientHello,
 * ServerHello, Certificate, CertificateVerify, and Finished.
 *
 * @param ctx			Handshake context
 * @param data			Received handshake message (plaintext)
 * @param dataLen		Length of received data
 * @param response		Output buffer for response messages (may be multiple)
 * @param responseLen	Pointer to output length
 * @return				1 on success, 0 on error
 */
int	tlsHandshakeProcess(t_tlsHandshakeCtx	*ctx,
						 const uint8_t		*data,
						 size_t				dataLen,
						 uint8_t			*response,
						 size_t				*responseLen);

/**
 * @brief Start handshake (client sends ClientHello)
 *
 * This function initiates the TLS handshake from the client side by
 * constructing and sending a ClientHello message. It includes the list
 * of supported cipher suites, generates a random client random value,
 * and prepares the initial key exchange parameters. The resulting
 * ClientHello message is written to the response buffer.
 *
 * @param ctx			Handshake context
 * @param cipherSuites	List of supported cipher suites
 * @param numSuites		Number of cipher suites
 * @param response		Output buffer for ClientHello message
 * @param responseLen	Pointer to output length
 * @return				1 on success, 0 on error
 */
int	tlsHandshakeStartClient(t_tlsHandshakeCtx	*ctx,
							 t_tlsCipherType	*cipherSuites,
							 size_t				numSuites,
							 uint8_t			*response,
							 size_t				*responseLen);

/**
 * @brief Start handshake (server receives ClientHello, sends ServerHello)
 *
 * This function processes a received ClientHello message from the client,
 * selects the appropriate cipher suite based on the client's list and
 * server capabilities, generates a server random value, and constructs
 * the ServerHello response. It also initiates key derivation for the
 * handshake traffic secrets.
 *
 * @param ctx				Handshake context
 * @param clientHello		Received ClientHello message
 * @param clientHelloLen	Length of ClientHello
 * @param response			Output buffer for ServerHello response
 * @param responseLen		Pointer to output length
 * @return					1 on success, 0 on error
 */
int	tlsHandshakeStartServer(t_tlsHandshakeCtx	*ctx,
							 const uint8_t		*clientHello,
							 size_t				clientHelloLen,
							 uint8_t			*response,
							 size_t				*responseLen);

/**
 * @brief Get current handshake state
 *
 * This utility function returns the current state of the handshake state
 * machine. It is useful for debugging, progress monitoring, and determining
 * which operations are valid at a given point in the handshake.
 *
 * @param ctx	Handshake context
 * @return		Current state
 */
t_tlsHandshakeState	tlsHandshakeGetState(const t_tlsHandshakeCtx *ctx);

/**
 * @brief Check if handshake is complete
 *
 * This function returns whether the handshake has successfully completed
 * and the connection is ready for application data. The handshake is
 * considered complete when both parties have exchanged and verified
 * Finished messages and the state is TLS_HS_STATE_CONNECTED.
 *
 * @param ctx	Handshake context
 * @return		1 if connected, 0 otherwise
 */
int	tlsHandshakeIsConnected(const t_tlsHandshakeCtx *ctx);

#endif /* BTLS_HANDSHAKE_H */
