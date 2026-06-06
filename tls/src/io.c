#include <errno.h>
#include <sys/socket.h>

#include "../../hajlib/include/hmemory.h"
#include "../includes/constants.h"

#include "../includes/io.h"

void	tlsIoInit(t_tlsIoctx *io, int socket, int isBlocking)
{
	if (!io) return;
	ft_bzero(io, sizeof(t_tlsIoctx));
	io->socket = socket;
	io->isBlocking = isBlocking;
}

int tlsIoHasPending(t_tlsIoctx *io)
{
	if (!io) return (0);
	return ((io->readBufLen - io->readBufPos > 0) || (io->writeBufLen > 0));
}

ssize_t	tlsIoReadRaw(t_tlsIoctx *io, uint8_t *buf, size_t len)
{
	ssize_t	n;

	if (!io || !buf) return (-1);
	
	n = recv(io->socket, buf, len, 0);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return (0);	/* Would block, return 0 */
	return (n);
}

ssize_t	tlsIoWriteRaw(t_tlsIoctx *io, const uint8_t *buf, size_t len)
{
	ssize_t	n;

	if (!io || !buf) return (-1);
	
	n = send(io->socket, buf, len, 0);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return (0);	/* Would block, return 0 */
	return (n);
}

int	tlsIoFlush(t_tlsIoctx *io)
{
	size_t	written;
	ssize_t	n;

	if (!io || io->writeBufLen == 0)
		return (0);
	
	written = 0;
	while (written < io->writeBufLen)
	{
		n = tlsIoWriteRaw(io, io->writeBuf + written, io->writeBufLen - written);
		if (n < 0)
			return (-1);
		if (n == 0 && !io->isBlocking)
		{
			/* Partial write in non-blocking mode */
			ft_memmove(io->writeBuf, io->writeBuf + written, io->writeBufLen - written);
			io->writeBufLen -= written;
			return (0);
		}
		written += n;
	}
	io->writeBufLen = 0;
	return (0);
}

ssize_t tlsIoDrainReadBuffer(t_tlsIoctx *io, uint8_t *buf, size_t len)
{
	size_t available;
	
	if (!io || !buf) return (-1);
	
	available = io->readBufLen - io->readBufPos;
	if (available == 0) return (0);
	
	if (len > available) len = available;
	ft_memcpy(buf, io->readBuf + io->readBufPos, len);
	io->readBufPos += len;
	
	/* If buffer is fully consumed, reset it */
	if (io->readBufPos >= io->readBufLen) {
		io->readBufLen = 0;
		io->readBufPos = 0;
	}
	
	return (len);
}

int	tlsIoReadRecord(t_tlsIoctx *io, uint8_t *contentType, uint8_t *data, size_t *dataLen)
{
	uint8_t	header[TLS_RECORD_HEADER_SIZE];
	size_t	recordLen;
	ssize_t	n;
	size_t	totalRead;

	if (!io || !contentType || !data || !dataLen)
		return (-1);
	
	/* Use buffered data first */
	if (io->readBufPos >= io->readBufLen)
	{
		/* Refill buffer */
		n = tlsIoReadRaw(io, io->readBuf, TLS_READ_BUFFER_SIZE);
		if (n <= 0)
			return (n);
		io->readBufLen = n;
		io->readBufPos = 0;
	}
	
	/* Ensure we have at least header size */
	if (io->readBufLen - io->readBufPos < TLS_RECORD_HEADER_SIZE)
	{
		/* Need more data */
		ft_memmove(io->readBuf, io->readBuf + io->readBufPos,
				   io->readBufLen - io->readBufPos);
		io->readBufLen -= io->readBufPos;
		io->readBufPos = 0;
		
		n = tlsIoReadRaw(io, io->readBuf + io->readBufLen, TLS_READ_BUFFER_SIZE - io->readBufLen);
		if (n <= 0)
			return (n);
		io->readBufLen += n;
	}
	
	/* Read header */
	ft_memcpy(header, io->readBuf + io->readBufPos, TLS_RECORD_HEADER_SIZE);
	io->readBufPos += TLS_RECORD_HEADER_SIZE;
	
	*contentType = header[0];
	recordLen = ((size_t)header[3] << 8) | header[4];
	
	if (recordLen > *dataLen)
	{
		/* Buffer too small, return error */
		return (-1);
	}
	
	/* Ensure we have the full record in buffer */
	totalRead = 0;
	while (io->readBufLen - io->readBufPos < recordLen)
	{
		/* Move remaining data to beginning */
		ft_memmove(io->readBuf, io->readBuf + io->readBufPos,
				   io->readBufLen - io->readBufPos);
		io->readBufLen -= io->readBufPos;
		io->readBufPos = 0;
		
		n = tlsIoReadRaw(io, io->readBuf + io->readBufLen, TLS_READ_BUFFER_SIZE - io->readBufLen);
		if (n <= 0)
			return (n);
		io->readBufLen += n;
		totalRead++;
		if (totalRead > TLS_IO_MAX_RETRIES)  /* Prevent infinite loop */
			return (-1);
	}
	
	/* Copy record data */
	ft_memcpy(data, io->readBuf + io->readBufPos, recordLen);
	io->readBufPos += recordLen;
	*dataLen = recordLen;
	
	return (1);
}

int	tlsIoWriteRecord(t_tlsIoctx *io, uint8_t contentType, const uint8_t *data, size_t dataLen)
{
	uint8_t	header[TLS_RECORD_HEADER_SIZE];
	
	if (!io || !data)
		return (-1);
	
	/* Build header */
	header[0] = contentType;
	header[1] = 0x03;  /* legacy_version major */
	header[2] = 0x03;  /* legacy_version minor */
	header[3] = (dataLen >> 8) & 0xFF;
	header[4] = dataLen & 0xFF;
	
	/* Ensure buffer has space */
	if (io->writeBufLen + TLS_RECORD_HEADER_SIZE + dataLen > TLS_WRITE_BUFFER_SIZE)
	{
		/* Flush buffer first */
		if (tlsIoFlush(io) != 0)
			return (-1);
	}
	
	/* Add to buffer */
	ft_memcpy(io->writeBuf + io->writeBufLen, header, TLS_RECORD_HEADER_SIZE);
	io->writeBufLen += TLS_RECORD_HEADER_SIZE;
	ft_memcpy(io->writeBuf + io->writeBufLen, data, dataLen);
	io->writeBufLen += dataLen;
	
	return (1);
}
