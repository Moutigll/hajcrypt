#ifndef BTLS_HANDSHAKE_HELLO_H
# define BTLS_HANDSHAKE_HELLO_H

# include "constants.h"
# include "extensions.h"

/**
 * @brief Common structure for ClientHello and ServerHello
 *
 * This structure contains fields shared between ClientHello and ServerHello
 * messages, allowing unified encoding and decoding. It includes both base
 * fields (version, random, session ID) and parsed extensions (supported_versions,
 * key_share, SNI, ALPN, PSK, etc.). Client-specific fields (cipherSuites) and
 * server-specific fields (selectedCipherSuite) are clearly separated.
 */
typedef struct s_tlsHello
{
	/* Common fields */
	uint16_t	legacyVersion;					/* 0x0303 for TLS 1.2 compatibility */
	uint8_t		random[32];						/* 32 random bytes */
	uint8_t		*sessionId;						/* Session ID (0-32 bytes) */
	size_t		sessionIdLen;
	
	/* Client-specific fields */
	uint16_t	*cipherSuites;					/* List of cipher suites (client) */
	size_t		numCipherSuites;
	uint8_t		*compressionMethods;			/* Compression methods (client) */
	size_t		numCompressionMethods;
	
	/* Server-specific fields */
	uint16_t	selectedCipherSuite;			/* Selected cipher suite (server) */
	uint8_t		selectedCompression;			/* Selected compression method (server) */
	
	/* Extensions */
	uint8_t			*rawExtensions;		/* Raw extension data */
	size_t			extensionsLen;
	t_tlsExtensions	extensions;			/* Parsed extensions for easy access */
}	t_tlsHello;



/**
 * @brief Initialises a t_tlsHello structure
 *
 * This function initialises all fields of a t_tlsHello structure to default
 * values (NULL pointers, zero lengths, etc.). It must be called before using
 * the structure, and tlsHelloFree() must be called to release allocated
 * resources.
 *
 * @param hello		Structure to initialise
 */
void	tlsHelloInit(t_tlsHello *hello);

/**
 * @brief Frees resources of a t_tlsHello structure
 *
 * This function frees all dynamically allocated memory associated with the
 * t_tlsHello structure, including sessionId, cipherSuites, extensions,
 * key shares, SNI hostname, ALPN protocols, and PSK data. After freeing,
 * the structure should not be reused without reinitialisation.
 *
 * @param hello		Structure to free
 */
void	tlsHelloFree(t_tlsHello *hello);

/**
 * @brief Decodes a ClientHello from wire format
 *
 * This function decodes a ClientHello message from wire format into a
 * t_tlsHello structure. It parses all fields and extensions, including
 * supported_versions, key_share, supported_groups, signature_algorithms,
 * SNI, ALPN, and PSK. The decoded data is stored in the structure with
 * dynamically allocated buffers that must be freed with tlsHelloFree().
 *
 * @param data		Received data
 * @param dataLen	Length of data
 * @param hello		Structure to fill
 * @param isServer	Non-zero if decoding a ServerHello, zero for ClientHello
 * @return			1 on success, 0 on error
 */
 int tlsDecodeHello(const uint8_t *data, size_t dataLen, t_tlsHello *hello, int isServer);

/**
 * @brief Builds a ServerHello from selections
 *
 * This function builds a ServerHello message based on the client's ClientHello
 * and the server's selections (version, cipher suite, group, and public key).
 * It populates a t_tlsHello structure and encodes it into wire format.
 * The resulting ServerHello can be sent directly to the client.
 *
 * @param serverHello		Server Hello structure to fill (must be initialised with tlsHelloInit())
 * @param clientHello		Client Hello
 * @param out				Output buffer
 * @param outLen			Length written (input: buffer size, output: actual length)
 * @return					1 on success, 0 on error
 */
int tlsBuildServerHello(t_tlsHello			*serverHello,
						const t_tlsHello	*clientHello,
						uint16_t 			selectedVersion,
						uint8_t				*out,	size_t	*outLen);

int		tlsPrintHello(const t_tlsHello *hello);

#endif /* BTLS_HANDSHAKE_HELLO_H */
