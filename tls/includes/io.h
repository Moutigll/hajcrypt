#ifndef BTLS_IO_H
# define BTLS_IO_H

# include <stdint.h>
# include <sys/types.h>

#include "constants.h"

/* Buffer sizes for TLS I/O context, corresponding to maximum TLS record size (16KB) */
# define TLS_READ_BUFFER_SIZE	TLS_MAX_FRAGMENT_LEN
# define TLS_WRITE_BUFFER_SIZE	TLS_MAX_FRAGMENT_LEN

# define TLS_IO_MAX_RETRIES 10

/**
 * @brief TLS I/O context for network communication
 *
 * This structure manages the network I/O for a TLS connection,
 * including buffering for partial reads and writes. It provides
 * efficient I/O by reading and writing in chunks, reducing the
 * number of system calls. The read buffer stores data that has
 * been read from the socket but not yet consumed by the TLS layer.
 * The write buffer stores data that has been queued for writing
 * but not yet sent to the socket.
 */
typedef struct s_tlsIoctx
{
	int		socket;							/* Socket file descriptor */
	int		isBlocking;						/* 1 = blocking, 0 = non-blocking */
	
	/* ---- Reading ---- */
	uint8_t	readBuf[TLS_READ_BUFFER_SIZE];	/* Read buffer for incoming data */
	size_t	readBufLen;						 /* Octets disponibles dans readBuf */
	size_t	readBufPos;						 /* Position de lecture dans readBuf */
	
	/* ---- Writing ---- */
	uint8_t	writeBuf[TLS_WRITE_BUFFER_SIZE];	/* Buffer d'écriture */
	size_t	writeBufLen;						/* Octets à envoyer (total) */
	size_t	writeBufPos;						/* ◄── MANQUANT ! Déjà envoyés */
	
	int		ioError;							/* Dernière erreur I/O */
}   t_tlsIoctx;

/**
 * @brief Initialize I/O context with a socket
 *
 * This function initialises the I/O context with the provided socket
 * and blocking mode. It zeros both read and write buffers and resets
 * all buffer pointers. The socket must already be connected.
 *
 * @param io			I/O context to initialize
 * @param socket		Socket file descriptor (already connected)
 * @param isBlocking	1 for blocking mode, 0 for non-blocking
 */
void	tlsIoInit(t_tlsIoctx *io, int socket, int isBlocking);

/**
 * @brief Check if there is pending data in read or write buffers
 *
 * @param io	I/O context
 * @return		1 if there is pending data, 0 otherwise
 */
int	tlsIoHasPending(t_tlsIoctx *io);

/**
 * @brief Read raw data from socket (non-TLS)
 *
 * This function reads raw bytes from the socket, bypassing the TLS
 * layer. It first checks the read buffer for any pending data and
 * returns that before reading from the socket. This is used internally
 * by the record reading functions to handle partial reads.
 *
 * @param io		I/O context
 * @param buf		Output buffer
 * @param len		Number of bytes to read
 * @return			Number of bytes read, -1 on error, 0 on EOF
 */
ssize_t	tlsIoReadRaw(t_tlsIoctx *io, uint8_t *buf, size_t len);

/**
 * @brief Write raw data to socket (non-TLS)
 *
 * This function writes raw bytes to the socket, bypassing the TLS
 * layer. It writes data directly to the socket, but may write fewer
 * bytes than requested if the socket buffer is full or in non-blocking
 * mode. For buffered writes, use tlsIoFlush().
 *
 * @param io		I/O context
 * @param buf		Data to write
 * @param len		Number of bytes to write
 * @return			Number of bytes written, -1 on error
 */
ssize_t	tlsIoWriteRaw(t_tlsIoctx *io, const uint8_t *buf, size_t len);

/**
 * @brief Flush write buffer to socket
 *
 * This function writes any pending data in the write buffer to the
 * socket. In blocking mode, it continues writing until the buffer
 * is empty or an error occurs. In non-blocking mode, it writes as
 * much as possible and returns.
 *
 * @param io		I/O context
 * @return			0 on success (all data written), -1 on error
 */
int		tlsIoFlush(t_tlsIoctx *io);

/**
 * @brief Drain remaining data from read buffer
 *
 * @param io	I/O context
 * @return		Number of bytes drained, -1 on error
 */
ssize_t	tlsIoDrainReadBuffer(t_tlsIoctx *io, uint8_t *buf, size_t len);

/**
 * @brief Read a TLS record from socket (handles fragmentation)
 *
 * This function reads a complete TLS record from the socket, handling
 * record header parsing and fragmentation. It reads the 5-byte record
 * header first, then reads the fragment of the specified length. The
 * function may need to be called multiple times untils all the data
 * has been recieved if the socket is non-blocking.
 * The content type of the record is returned in the contentType parameter.
 *
 * @param io			I/O context
 * @param data			Output buffer for record data
 * @param dataLen		[in] Buffer size, [out] Data length
 * @return				1 on success, 0 on EOF, -1 on error
 */
int		tlsIoReadRecord(t_tlsIoctx *io, uint8_t *data, size_t *dataLen);

/**
 * @brief Write a TLS record to socket
 *
 * This function writes a TLS record to the socket. The record consists
 * of a 5-byte header (content type, legacy version, length) followed
 * by the fragment data. If using buffered I/O, the record is appended
 * to the write buffer; use tlsIoFlush() to send buffered records.
 *
 * @param io			I/O context
 * @param contentType	TLS record content type (0x14 for handshake, 0x17 for app data, etc.)
 * @param data			Record data
 * @param dataLen		Data length
 * @return				1 on success, -1 on error
 */
int		tlsIoWriteRecord(t_tlsIoctx *io, uint8_t contentType, const uint8_t *data, size_t dataLen);

#endif /* BTLS_IO_H */
