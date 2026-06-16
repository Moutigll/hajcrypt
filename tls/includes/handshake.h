#ifndef BTLS_HANDSHAKE_H
# define BTLS_HANDSHAKE_H

# include "btls.h"

/**
 * @brief Initialises a TLS handshake context
 *
 * This function initialises the handshake context with the specified role
 * and hash algorithm. It must be called before any handshake operations.
 *
 * @param ctx		Handshake context to initialise
 * @param isClient	1 for client mode, 0 for server mode
 * @param hash		Hash algorithm for transcript (SHA-256 or SHA-384)
 */
void	tlsHandshakeInit(t_tlsHandshakeCtx *ctx, int isClient, const t_hash *hash);

/**
 * @brief Frees a TLS handshake context
 *
 * This function securely zeroises and frees all resources associated with
 * the handshake context, including key exchange context, certificates,
 * and record protection contexts.
 *
 * @param ctx		Handshake context to free
 */
void	tlsHandshakeFree(t_tlsHandshakeCtx *ctx);

/**
 * @brief Updates the transcript hash with a handshake message
 *
 * This function adds a handshake message to the running transcript hash.
 * The message is prefixed with its 4-byte header (type + length).
 *
 * @param ctx		Handshake context
 * @param msgType	Handshake message type
 * @param data		Message body
 * @param dataLen	Message body length
 * @return			1 on success, 0 on error
 */
int		transcriptUpdate(t_tlsHandshakeCtx *ctx, uint8_t msgType, const uint8_t *data, size_t dataLen);

int		transcriptUpdateRaw(t_tlsHandshakeCtx *ctx, const uint8_t *fullHandshakeMsg, size_t fullLen);

/**
 * @brief Gets the current transcript hash
 *
 * This function finalises the current transcript hash and writes the
 * digest to the output buffer.
 *
 * @param ctx		Handshake context
 * @param out		Output buffer for hash digest
 */
void	transcriptGetHash(t_tlsHandshakeCtx *ctx, uint8_t *out);

/**
 * @brief Checks if the handshake is complete
 *
 * This function returns whether the handshake has successfully completed
 * and the connection is ready for application data.
 *
 * @param ctx		Handshake context
 * @return			1 if connected, 0 otherwise
 */
int		tlsHandshakeIsConnected(const t_tlsHandshakeCtx *ctx);










/* ============================================================================
 * TLS 1.3 Handshake Functions
 * ============================================================================ */

/**
 * @brief Performs TLS 1.3 handshake from server side
 *
 * This function executes the TLS 1.3 handshake on the server side,
 * processing ClientHello and generating ServerHello, EncryptedExtensions,
 * Certificate, CertificateVerify, and Finished messages.
 *
 * @param ctx				TLS context (contains handshake state)
 * @return					1 on success, 0 on error
 */
int		tls13ServerHandshake(t_tlsCtx *ctx);

/**
 * @brief Performs TLS 1.3 handshake from client side
 *
 * This function executes the TLS 1.3 handshake on the client side,
 * generating ClientHello and processing server responses including
 * ServerHello, EncryptedExtensions, Certificate, CertificateVerify,
 * and Finished.
 *
 * @param ctx				TLS context (contains handshake state)
 * @return					1 on success, 0 on error
 */
int		tls13ClientHandshake(t_tlsCtx *ctx);

/**
 * @brief Sends an encrypted handshake message (TLS 1.3)
 *
 * This function encrypts and sends a handshake message using the current
 * handshake traffic keys.
 *
 * @param ctx		TLS context
 * @param msg		Handshake message to send
 * @param msgLen	Length of the message
 * @return			1 on success, 0 on error
 */
int		tls13SendEncryptedMessage(t_tlsCtx *ctx, const uint8_t *msg, size_t msgLen, uint8_t contentType);

/**
 * @brief Reads an encrypted handshake message (TLS 1.3)
 *
 * This function reads and decrypts an encrypted handshake message using
 * the current handshake traffic keys.
 *
 * @param ctx		TLS context
 * @param msg		Output buffer for the message
 * @param msgLen	Output message length
 * @param expectedContentType If non-zero, the expected content type of the decrypted message (e.g. TLS_RT_HANDSHAKE)
 * @return			1 on success, 0 on error
 */
int		tls13ReadEncryptedHandshake(t_tlsCtx *ctx, uint8_t *msg, size_t *msgLen, uint8_t expectedContentType);

/**
 * @brief Builds a TLS 1.3 Finished message
 *
 * This function constructs a Finished message using the provided traffic
 * secret and the current transcript hash.
 *
 * @param ctx			Handshake context
 * @param trafficSecret	Traffic secret for finished verification
 * @param secretLen		Length of the traffic secret
 * @param out			Output buffer for Finished message
 * @param outLen		Output length
 * @return				1 on success, 0 on error
 */
int		tls13BuildFinished(t_tlsHandshakeCtx	*ctx,
						   const uint8_t		*trafficSecret,	size_t	secretLen,
						   uint8_t				*out,			size_t	*outLen);

/**
 * @brief Verifies a TLS 1.3 Finished message
 *
 * This function verifies a received Finished message using the provided
 * traffic secret and the current transcript hash.
 *
 * @param ctx			Handshake context
 * @param trafficSecret	Traffic secret for finished verification
 * @param secretLen		Length of the traffic secret
 * @param finished		Received Finished message
 * @param finishedLen	Length of the Finished message
 * @return				1 if valid, 0 otherwise
 */
int		tls13VerifyFinished(t_tlsHandshakeCtx	*ctx,
							const uint8_t		*trafficSecret,	size_t	secretLen,
							const uint8_t		*finished,		size_t	finishedLen);

/**
 * @brief Builds a TLS 1.3 Certificate message
 *
 * This function constructs a Certificate message containing the server's
 * certificate chain.
 *
 * @param ctx		Handshake context
 * @param out		Output buffer for Certificate message
 * @param outLen	Output length
 * @return			1 on success, 0 on error
 */
int		tls13BuildCertificate(t_tlsHandshakeCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Builds a TLS 1.3 CertificateVerify message
 *
 * This function constructs a CertificateVerify message containing a
 * signature over the transcript hash using the server's private key.
 *
 * @param ctx		Handshake context
 * @param out		Output buffer for CertificateVerify message
 * @param outLen	Output length
 * @return			1 on success, 0 on error
 */
int		tls13BuildCertificateVerify(t_tlsCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Builds a TLS 1.3 EncryptedExtensions message
 *
 * This function constructs an EncryptedExtensions message containing
 * negotiated extensions that are not part of ServerHello.
 *
 * @param ctx		Handshake context
 * @param out		Output buffer for EncryptedExtensions message
 * @param outLen	Output length
 * @return			1 on success, 0 on error
 */
int		tls13BuildEncryptedExtensions(t_tlsHandshakeCtx *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Sends a TLS alert (TLS 1.3)
 *
 * This function sends an encrypted alert message over the TLS connection.
 *
 * @param ctx			TLS context
 * @param level			Alert level (1 = warning, 2 = fatal)
 * @param description	Alert description
 * @return				1 on success, 0 on error
 */
int		tls13SendAlert(t_tlsCtx *ctx, uint8_t level, uint8_t description);










/* ============================================================================
 * TLS 1.2 Handshake Functions
 * ============================================================================ */

/**
 * @brief Performs TLS 1.2 handshake from server side
 *
 * This function executes the TLS 1.2 handshake on the server side,
 * processing ClientHello and generating ServerHello, Certificate,
 * ServerKeyExchange, ServerHelloDone, and handling ClientKeyExchange,
 * ChangeCipherSpec, and Finished messages.
 *
 * @param ctx				TLS context (contains handshake state)
 * @param serverHello		Output buffer for ServerHello message
 * @param serverHelloLen	Length of ServerHello (output)
 * @return					1 on success, 0 on error
 */
int		tls12ServerHandshake(t_tlsCtx *ctx, uint8_t *serverHello, size_t serverHelloLen);

/**
 * @brief Performs TLS 1.2 handshake from client side
 *
 * This function executes the TLS 1.2 handshake on the client side,
 * generating ClientHello and processing ServerHello, Certificate,
 * ServerKeyExchange, ServerHelloDone, then sending ClientKeyExchange,
 * ChangeCipherSpec, and Finished.
 *
 * @param ctx				TLS context (contains handshake state)
 * @return					1 on success, 0 on error
 */
int		tls12ClientHandshake(t_tlsCtx *ctx);

/**
 * @brief Sends Certificate message (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12SendCertificate(t_tlsCtx *ctx);

/**
 * @brief Sends ServerKeyExchange message (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12SendServerKeyExchange(t_tlsCtx *ctx);

/**
 * @brief Sends ServerHelloDone message (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12SendServerHelloDone(t_tlsCtx *ctx);

/**
 * @brief Receives and processes ClientKeyExchange (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12RecvClientKeyExchange(t_tlsCtx *ctx);

/**
 * @brief Receives and verifies CertificateVerify (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12RecvCertificateVerify(t_tlsCtx *ctx);

/**
 * @brief Receives ChangeCipherSpec (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12RecvChangeCipherSpec(t_tlsCtx *ctx);

/**
 * @brief Sends ChangeCipherSpec (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12SendChangeCipherSpec(t_tlsCtx *ctx);

/**
 * @brief Sends Finished message (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12SendFinished(t_tlsCtx *ctx);

/**
 * @brief Receives and verifies Finished message (TLS 1.2)
 *
 * @param ctx		TLS context
 * @return			1 on success, 0 on error
 */
int		tls12RecvFinished(t_tlsCtx *ctx);










/* ============================================================================
 * Common Helpers
 * ============================================================================ */

/**
 * @brief Encodes a handshake message into wire format
 *
 * This function encodes a handshake message (type + length + body) into
 * the standard TLS wire format. The output is a 4-byte header followed
 * by the message body.
 *
 * @param msgType	Handshake message type
 * @param body		Message body
 * @param bodyLen	Message body length
 * @param out		Output buffer
 * @param outLen	Length written (input: buffer size, output: actual length)
 * @return			1 on success, 0 on error
 */
int		handshakeEncode(uint8_t			msgType,
						const uint8_t	*body,	size_t	bodyLen,
						uint8_t			*out,	size_t	*outLen);

/**
 * @brief Decodes a handshake message from wire format
 *
 * This function decodes a handshake message from wire format, extracting
 * the message type, body pointer, and body length. The body pointer points
 * directly into the input data and must not be freed.
 *
 * @param data		Input data (handshake message)
 * @param dataLen	Length of input data
 * @param msgType	Output: handshake message type
 * @param body		Output: pointer to message body (within input data)
 * @param bodyLen	Output: message body length
 * @return			1 on success, 0 on error
 */
int		handshakeDecode(const uint8_t *data, size_t dataLen, uint8_t *msgType, const uint8_t **body, size_t *bodyLen);



/**
 * @brief Reads a handshake message (plaintext or encrypted)
 *
 * This function reads a complete handshake message from the TLS connection,
 * optionally decrypting it if encrypted.
 *
 * @param ctx			TLS context
 * @param msg			Output buffer for handshake message
 * @param msgLen		Output message length
 * @param encrypted		1 if record is encrypted, 0 for plaintext
 * @return				1 on success, 0 on error
 */
int		tlsReadHandshakeMessage(t_tlsCtx *ctx, uint8_t *msg, size_t *msgLen, int encrypted);

/**
 * @brief Writes a handshake message (plaintext or encrypted)
 *
 * This function writes a handshake message to the TLS connection,
 * optionally encrypting it if required.
 *
 * @param ctx			TLS context
 * @param msg			Handshake message to send
 * @param msgLen		Message length
 * @param encrypted		1 to encrypt, 0 to send plaintext
 * @return				1 on success, 0 on error
 */
int		tlsWriteHandshakeMessage(t_tlsCtx *ctx, const uint8_t *msg, size_t msgLen, int encrypted);

/**
 * @brief Negotiates TLS version
 *
 * This function selects a mutually supported TLS version based on the
 * client's supported versions and server's preferences.
 *
 * @param clientVersions	Client's supported versions list
 * @param numVersions		Number of client versions
 * @param serverPref		Server's version preference
 * @param selected			Output: selected version
 * @return					1 if a version was selected, 0 otherwise
 */
int		negotiateVersion(const uint16_t *clientVersions, size_t numVersions, t_tlsVersionPref serverPref, uint16_t *selected);

/**
 * @brief Negotiates ALPN protocol
 *
 * This function selects a mutually supported ALPN protocol based on
 * client's list and server's supported list.
 *
 * @param clientProtocols	Client's ALPN protocols
 * @param numClientProtocols Number of client protocols
 * @param serverProtocols	Server's supported ALPN protocols
 * @param numServerProtocols Number of server protocols
 * @param selected			Output: selected protocol name
 * @return					1 if a protocol was selected, 0 otherwise
 */
int		negotiateAlpn(const char **clientProtocols, size_t numClientProtocols,
					  const char **serverProtocols, size_t numServerProtocols,
					  const char **selected);

/**
 * @brief Handles a received TLS alert message
 *
 * This function processes a received alert message and updates the
 * connection state accordingly.
 *
 * @param ctx			TLS context
 * @param data			Alert data
 * @param dataLen		Length of alert data
 * @return				1 if alert is non-fatal, 0 if fatal
 */
int		tlsHandleAlert(t_tlsCtx *ctx, const uint8_t *data, size_t dataLen);

/**
 * @brief Sets an error on the TLS context
 *
 * This function records an error code and human-readable message on the
 * TLS context for later retrieval.
 *
 * @param ctx		TLS context
 * @param code		Error code (TLS_ERR_*)
 * @param msg		Human-readable error message
 */
void	tlsSetError(t_tlsCtx *ctx, int code, const char *msg);

#endif /* BTLS_HANDSHAKE_H */
