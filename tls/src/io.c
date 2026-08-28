#define _GNU_SOURCE
#include <errno.h>
#include <string.h>


#ifdef _WIN32
	#include <windows.h>
	
	/* Définir __errno_location pour MinGW */
	int *__errno_location(void) {
		static int errno_value = 0;
		errno_value = GetLastError();
		return &errno_value;
	}
#else
	#include <sys/socket.h>
#endif

#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hmemory.h"
#include "../includes/btls.h"

#include "../includes/io.h"


static const char *tlsRecordTypeToString(uint8_t type)
{
	switch (type) {
		case TLS_RT_CHANGE_CIPHER_SPEC:	return "ChangeCipherSpec";
		case TLS_RT_ALERT:				return "Alert";
		case TLS_RT_HANDSHAKE:			return "Handshake";
		case TLS_RT_APPLICATION_DATA:	return "ApplicationData";
		default:						return "Unknown";
	}
}

static void printHexRaw(const uint8_t *data, size_t len)
{
	return;
	if (!data || len == 0) return;
	BTLS_DEBUG("Printing record type %s (%zu bytes):", tlsRecordTypeToString(data[0]), len);
	for (size_t i = 0; i < len; i++)
	{
		if (i % 16 == 0)
			ft_printf("%04zx: ", i);
		ft_printf("%02x ", data[i]);
		if ((i + 1) % 8 == 0)
			ft_printf(" ");
		if ((i + 1) % 16 == 0 || i + 1 == len)
		{
			size_t j;
			for (j = i - (i % 16); j <= i; j++)
			{
				if (j % 16 == 0)
					ft_printf(" ");
				if (data[j] >= 32 && data[j] <= 126)
					ft_printf("%c", data[j]);
				else
					ft_printf(".");
			}
			ft_printf("\n");
		}
	}
}


void	tlsIoInit(t_tlsIoctx *io, int socket, int isBlocking)
{
	if (!io) return;
	ft_bzero(io, sizeof(t_tlsIoctx));
	io->socket		= socket;
	io->isBlocking	= isBlocking;
}

int		tlsIoHasPending(t_tlsIoctx *io)
{
	if (!io) return (0);
	return ((io->readBufLen - io->readBufPos > 0)
		|| (io->writeBufLen - io->writeBufPos > 0));
}

ssize_t	tlsIoReadRaw(t_tlsIoctx *io, uint8_t *buf, size_t len)
{
	ssize_t n;

	if (!io || !buf) return (-1);

	n = recv(io->socket, (void *)buf, len, 0);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) { 
			io->ioError = TLS_ERR_WANT_READ;
			return (0);
		}
		io->ioError = TLS_ERR_IO;
		return (-1);
	}
	if (n == 0) {
		io->ioError = TLS_ERR_EOF;
		return (0);
	}
	printHexRaw(buf, (size_t)n);
	return (n);
}

ssize_t	tlsIoWriteRaw(t_tlsIoctx *io, const uint8_t *buf, size_t len)
{
	ssize_t n;

	if (!io || !buf) return (-1);

	n = send(io->socket,(const void *)buf, len, 0);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			io->ioError = TLS_ERR_WANT_WRITE;
			return (0);
		}
		io->ioError = TLS_ERR_IO;
		return (-1);
	}
	printHexRaw(buf, (size_t)n);
	return (n);
}

/**
 * @brief Compact the write buffer by moving unsent data to the beginning.
 *
 * This function is called when there is not enough space in the write buffer
 * to accommodate a new TLS record. It moves any unsent data to the beginning
 * of the buffer, freeing up space at the end for new data.
 *
 * @param io	I/O context
 */
static void tlsIoCompactWriteBuf(t_tlsIoctx *io)
{
	size_t remaining;

	if (io->writeBufPos == 0)
		return;

	remaining = io->writeBufLen - io->writeBufPos;
	if (remaining > 0)
		ft_memmove(io->writeBuf, io->writeBuf + io->writeBufPos, remaining);

	io->writeBufLen = remaining;
	io->writeBufPos = 0;
}

int tlsIoFlush(t_tlsIoctx *io)
{
	ssize_t n;
	if (!io || io->writeBufLen == 0)
		return (1);

	while (io->writeBufPos < io->writeBufLen) {
		n = tlsIoWriteRaw(io,
						  io->writeBuf + io->writeBufPos,
						  io->writeBufLen - io->writeBufPos);
		if (n < 0)
			return (-1);
		if (n == 0 && !io->isBlocking)
			return (0);
		io->writeBufPos += (size_t)n;
	}

	io->writeBufLen = 0;
	io->writeBufPos = 0;
	return (1);
}

int tlsIoWriteRecord(t_tlsIoctx *io, uint8_t contentType, const uint8_t *data, size_t dataLen)
{
	size_t	needed;
	size_t	available;
	size_t	offset;

	if (!io || !data)
		return (-1);

	if (contentType != 0)
		needed = TLS_RECORD_HEADER_SIZE + dataLen;  /* header + fragment */
	else
		needed = dataLen;						   /* no header, just raw data */

	available = TLS_WRITE_BUFFER_SIZE - (io->writeBufLen - io->writeBufPos);

	if (needed > available) {
		int flush_ret = tlsIoFlush(io);
		if (flush_ret < 0)
			return (-1);

		available = TLS_WRITE_BUFFER_SIZE - (io->writeBufLen - io->writeBufPos);

		if (needed > available) {
			tlsIoCompactWriteBuf(io);
			available = TLS_WRITE_BUFFER_SIZE - (io->writeBufLen - io->writeBufPos);

			if (needed > available) {
				io->ioError = TLS_ERR_WANT_WRITE;
				return (0);
			}
		}
	}

	offset = io->writeBufLen;

	if (contentType != 0) {
		BTLS_DEBUG("Writing TLS record header: type=%s, length=%zu", tlsRecordTypeToString(contentType), dataLen);
		io->writeBuf[offset + 0] = contentType;
		io->writeBuf[offset + 1] = 0x03;
		io->writeBuf[offset + 2] = 0x03;
		io->writeBuf[offset + 3] = (dataLen >> 8) & 0xFF;
		io->writeBuf[offset + 4] = dataLen & 0xFF;
		ft_memcpy(io->writeBuf + offset + TLS_RECORD_HEADER_SIZE, data, dataLen);
	} else
		ft_memcpy(io->writeBuf + offset, data, dataLen);

	io->writeBufLen += needed;
	return (1);
}

ssize_t tlsIoDrainReadBuffer(t_tlsIoctx *io, uint8_t *buf, size_t len)
{
	size_t available;

	if (!io || !buf) return (-1);

	available = io->readBufLen - io->readBufPos;
	if (available == 0) return (0);

	if (len > available)
		len = available;

	ft_memcpy(buf, io->readBuf + io->readBufPos, len);
	io->readBufPos += len;

	if (io->readBufPos >= io->readBufLen)
	{
		io->readBufLen = 0;
		io->readBufPos = 0;
	}

	return ((ssize_t)len);
}

/**
 * @brief Compact the read buffer by moving unread data to the beginning.
 *
 * This function is called when there is not enough space in the read buffer
 * to accommodate a new TLS record. It moves any unread data to the beginning
 * of the buffer, freeing up space at the end for new data.
 *
 * @param io	I/O context
 */
static void tlsIoCompactReadBuf(t_tlsIoctx *io)
{
	size_t remaining;

	if (io->readBufPos == 0)
		return;

	remaining = io->readBufLen - io->readBufPos;
	if (remaining > 0)
		ft_memmove(io->readBuf, io->readBuf + io->readBufPos, remaining);

	io->readBufLen = remaining;
	io->readBufPos = 0;
}

int tlsIoReadRecord(t_tlsIoctx *io, uint8_t *data, size_t *dataLen)
{
	size_t  recordLen;
	ssize_t n;

	if (!io || !data || !dataLen)
		return (-1);

	while (io->readBufLen - io->readBufPos < TLS_RECORD_HEADER_SIZE)
	{
		tlsIoCompactReadBuf(io);
		n = tlsIoReadRaw(io, io->readBuf + io->readBufLen, TLS_READ_BUFFER_SIZE - io->readBufLen);
		if (n <= 0) return ((int)n);
		io->readBufLen += (size_t)n;
	}

	recordLen = ((size_t)io->readBuf[io->readBufPos + 3] << 8) | io->readBuf[io->readBufPos + 4];

	if (recordLen > TLS_MAX_FRAGMENT_LEN) {
		io->ioError = TLS_ERR_PROTOCOL;
		return (-1);
	}

	size_t totalLen = TLS_RECORD_HEADER_SIZE + recordLen;
	if (totalLen > *dataLen) {
		io->ioError = TLS_ERR_INTERNAL;
		return (-1);
	}

	while (io->readBufLen - io->readBufPos < totalLen)
	{
		tlsIoCompactReadBuf(io);
		n = tlsIoReadRaw(io, io->readBuf + io->readBufLen, TLS_READ_BUFFER_SIZE - io->readBufLen);
		if (n <= 0) return ((int)n);
		io->readBufLen += (size_t)n;
	}

	ft_memcpy(data, io->readBuf + io->readBufPos, totalLen);
	io->readBufPos += totalLen;
	*dataLen = totalLen;

	return (1);
}
