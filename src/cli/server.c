#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <windows.h>
#else
	#include <sys/epoll.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <fcntl.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/types.h>
#endif

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/cli/password.h"
#include "../../includes/utils/utils.h"

#include "../../includes/cli/tls.h"

static int g_debug_msg   = 0;
static int g_debug_state = 0;
static int g_debug_trace = 0;

static t_server g_server;

#ifdef _WIN32
	/* Redefine linux-specific functions and types for Windows.
	 * Moved here (after tls.h and g_server) because this shim needs
	 * MAX_CLIENTS and g_server, which aren't available earlier in the file. */
	#ifndef EPOLLIN
		#define EPOLLIN		0x001
		#define EPOLLOUT	0x004
		#define EPOLLERR	0x008
		#define EPOLLHUP	0x010
		#define EPOLLET		0x80000000
	#endif
	#ifndef EPOLL_CTL_ADD
		#define EPOLL_CTL_ADD	1
		#define EPOLL_CTL_MOD	2
		#define EPOLL_CTL_DEL	3
	#endif
	#ifndef EPOLL_CLOEXEC
		#define EPOLL_CLOEXEC	0
	#endif
	#ifndef SOCK_NONBLOCK
		#define SOCK_NONBLOCK	0
		#define SOCK_CLOEXEC	0
	#endif

	/* Redefine epoll_event structure for Windows.
	 * data is now a union (like the real epoll_event) so that
	 * events[i].data.ptr compiles, matching the rest of the code. */
	typedef struct epoll_event {
		uint32_t	events;
		union {
			void	*ptr;
		}		data;
	} epoll_event;

	/* Redefine close for Windows. Defined only now (after windows.h,
	 * hajlib.h and friends are already parsed) so it can no longer
	 * rewrite an unrelated close() prototype pulled in by those
	 * headers (e.g. via <io.h>) into a conflicting closesocket() one. */
	#ifdef close
		#undef close
	#endif
	#define close(fd) closesocket(fd)

	/* Static storage for Windows select() event loop */
	static fd_set g_readfds, g_writefds, g_exceptfds;
	static int g_maxfd = 0;

	/* Windows select() based epoll implementation */
	static int epoll_create1(int flags) {
		(void)flags;
		FD_ZERO(&g_readfds);
		FD_ZERO(&g_writefds);
		FD_ZERO(&g_exceptfds);
		g_maxfd = 0;
		return (0); /* Return dummy epoll fd */
	}

	static int epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
		(void)epfd;
		if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
			if (ev->events & EPOLLIN)
				FD_SET(fd, &g_readfds);
			if (ev->events & EPOLLOUT)
				FD_SET(fd, &g_writefds);
			if (ev->events & EPOLLERR)
				FD_SET(fd, &g_exceptfds);
			if (fd > g_maxfd)
				g_maxfd = fd;
		} else if (op == EPOLL_CTL_DEL) {
			FD_CLR(fd, &g_readfds);
			FD_CLR(fd, &g_writefds);
			FD_CLR(fd, &g_exceptfds);
			/* Recalculate maxfd if needed */
			if (fd == g_maxfd) {
				g_maxfd = 0;
				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (g_server.clients[i].fd >= 0 && g_server.clients[i].fd > g_maxfd)
						g_maxfd = g_server.clients[i].fd;
				}
				if (g_server.serverFd > g_maxfd)
					g_maxfd = g_server.serverFd;
			}
		}
		return (0);
	}

	static int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
		(void)epfd;
		fd_set readfds, writefds, exceptfds;
		struct timeval tv;
		struct timeval *ptv = NULL;
		int n, count = 0;

		if (timeout >= 0) {
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout % 1000) * 1000;
			ptv = &tv;
		}

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);

		/* Add server socket */
		if (g_server.serverFd >= 0) {
			FD_SET(g_server.serverFd, &readfds);
			if (g_server.serverFd > g_maxfd)
				g_maxfd = g_server.serverFd;
		}

		/* Add all clients */
		for (size_t i = 0; i < MAX_CLIENTS; i++) {
			if (g_server.clients[i].fd >= 0) {
				int fd = g_server.clients[i].fd;
				if (FD_ISSET(fd, &g_readfds))
					FD_SET(fd, &readfds);
				if (FD_ISSET(fd, &g_writefds))
					FD_SET(fd, &writefds);
				if (FD_ISSET(fd, &g_exceptfds))
					FD_SET(fd, &exceptfds);
				if (fd > g_maxfd)
					g_maxfd = fd;
			}
		}

		n = select(g_maxfd + 1, &readfds, &writefds, &exceptfds, ptv);
		if (n <= 0)
			return (n);

		/* Check server socket */
		if (FD_ISSET(g_server.serverFd, &readfds) && count < maxevents) {
			events[count].events = EPOLLIN;
			events[count].data.ptr = &g_server.serverFd;
			count++;
		}

		/* Check clients */
		for (size_t i = 0; i < MAX_CLIENTS && count < maxevents; i++) {
			if (g_server.clients[i].fd >= 0) {
				int fd = g_server.clients[i].fd;
				events[count].events = 0;
				if (FD_ISSET(fd, &readfds))
					events[count].events |= EPOLLIN;
				if (FD_ISSET(fd, &writefds))
					events[count].events |= EPOLLOUT;
				if (FD_ISSET(fd, &exceptfds))
					events[count].events |= EPOLLERR;
				if (events[count].events) {
					events[count].data.ptr = &g_server.clients[i];
					count++;
				}
			}
		}

		return (count);
	}

	/* Non-blocking helper for Windows */
	static int set_nonblocking(int fd) {
		u_long mode = 1;
		return ioctlsocket(fd, FIONBIO, &mode);
	}
#endif

static const tFtLongOption g_serverLongOpts[] = {
	{"cert",			FT_GETOPT_REQUIRED_ARGUMENT,	'c'},
	{"key",				FT_GETOPT_REQUIRED_ARGUMENT,	'k'},
	{"passin",			FT_GETOPT_REQUIRED_ARGUMENT,	'a'},
	{"port",			FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"tls12",			FT_GETOPT_NO_ARGUMENT,			'2'},
	{"tls13",			FT_GETOPT_NO_ARGUMENT,			'3'},
	{"cipher",			FT_GETOPT_REQUIRED_ARGUMENT,	'C'},
	{"ciphersuites",	FT_GETOPT_REQUIRED_ARGUMENT,	'E'},
	{"www",				FT_GETOPT_NO_ARGUMENT,			'w'},
	{"WWW",				FT_GETOPT_NO_ARGUMENT,			'W'},
	{"HTTP",			FT_GETOPT_NO_ARGUMENT,			0x202},
	{"http",			FT_GETOPT_NO_ARGUMENT,			'H'},
	{"nbio",			FT_GETOPT_NO_ARGUMENT,			'B'},
	{"async",			FT_GETOPT_NO_ARGUMENT,			'Y'},
	{"middlebox",		FT_GETOPT_NO_ARGUMENT,			'M'},
	{"nomiddlebox",		FT_GETOPT_NO_ARGUMENT,			'N'},
	{"curves",			FT_GETOPT_REQUIRED_ARGUMENT,	'R'},
	{"groups",			FT_GETOPT_REQUIRED_ARGUMENT,	'O'},
	{"notickets",		FT_GETOPT_NO_ARGUMENT,			'Z'},
	{"sessout",			FT_GETOPT_REQUIRED_ARGUMENT,	'S'},
	{"sessin",			FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"keylog",			FT_GETOPT_REQUIRED_ARGUMENT,	'K'},
	{"msg",				FT_GETOPT_NO_ARGUMENT,			'm'},
	{"debug",			FT_GETOPT_NO_ARGUMENT,			'd'},
	{"state",			FT_GETOPT_NO_ARGUMENT,			's'},
	{"trace",			FT_GETOPT_NO_ARGUMENT,			't'},
	{"accept",			FT_GETOPT_REQUIRED_ARGUMENT,	'A'},
	{"timeout",			FT_GETOPT_REQUIRED_ARGUMENT,	'T'},
	{"proxy",			FT_GETOPT_REQUIRED_ARGUMENT,	'P'},
	{"unix",			FT_GETOPT_REQUIRED_ARGUMENT,	'U'},
	{"ipv4",			FT_GETOPT_NO_ARGUMENT,			'4'},
	{"ipv6",			FT_GETOPT_NO_ARGUMENT,			'6'},
	{"help",			FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL, 0, 0}
};

static void printServerHelp(void)
{
	ft_printf("Usage: ft_ssl server [options]\n");
	ft_printf("Options:\n");
	ft_printf("  -c, --cert   <file>       Server certificate (PEM)\n");            // implemented
	ft_printf("  -k, --key    <file>       Server private key (PEM)\n");            // implemented
	ft_printf("  -a, --passin <arg>        Password for private key\n");            // implemented
	ft_printf("  -p, --port   <port>       Listening port (default 4433)\n");       // implemented
	ft_printf("  -A, --accept <host:port>  Bind to specific address/port\n");       // implemented
	ft_printf("  -2, --tls12               Enable TLS 1.2\n");                      // implemented
	ft_printf("  -3, --tls13               Enable TLS 1.3 (default)\n");            // implemented
	ft_printf("  -C, --cipher <suites>     TLS 1.2 cipher suites\n");               // not implemented
	ft_printf("  -E, --ciphersuites <s>    TLS 1.3 cipher suites\n");               // not implemented
	ft_printf("  -w, --www                 Respond to HTTP with a simple page\n");  // not implemented
	ft_printf("  -W, --WWW                 Respond to HTTP with CGI\n");            // not implemented
	ft_printf("      --HTTP                HTTP mode\n");                           // not implemented
	ft_printf("  -H, --http                HTTP mode (alias)\n");                   // not implemented
	ft_printf("  -B, --nbio                Non-blocking I/O (default)\n");          // implemented
	ft_printf("  -Y, --async               Asynchronous mode\n");                   // not implemented
	ft_printf("  -M, --middlebox           Enable middlebox compatibility (default)\n"); // implemented
	ft_printf("  -N, --nomiddlebox         Disable middlebox compatibility\n");     // implemented
	ft_printf("  -R, --curves <curves>     EC curves\n");                           // not implemented
	ft_printf("  -O, --groups <groups>     DH groups\n");                           // not implemented
	ft_printf("  -Z, --notickets           Disable session tickets\n");             // not implemented
	ft_printf("  -S, --sessout <file>      Save session to file\n");                // not implemented
	ft_printf("  -i, --sessin  <file>      Load session from file\n");              // not implemented
	ft_printf("  -K, --keylog  <file>      Write key log to file\n");               // not implemented
	ft_printf("  -m, --msg                 Show protocol messages\n");              // not implemented
	ft_printf("  -d, --debug               Debug mode\n");                          // not implemented
	ft_printf("  -s, --state               Print handshake state changes\n");       // not implemented
	ft_printf("  -t, --trace               Trace protocol details\n");              // not implemented
	ft_printf("  -T, --timeout <sec>       Idle timeout (seconds)\n");              // implemented
	ft_printf("  -P, --proxy   <host:port> Proxy\n");                               // not implemented
	ft_printf("  -U, --unix    <path>      Unix socket\n");                         // not implemented
	ft_printf("  -4, --ipv4                Use IPv4 only\n");                       // implemented
	ft_printf("  -6, --ipv6                Use IPv6 only\n");                       // implemented
	ft_printf("  -h, --help                Show this help\n");                      // implemented
}

static int parseServerArgs(int argc, char **argv, t_serverOptions *opts)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts = "a:c:k:p:A:MNT:U:4h23wWHC:E:R:O:Z:S:i:K:mdstP:Y6B";

	ft_bzero(opts, sizeof(t_serverOptions));
	/* defaults */
	opts->port		= DEFAULT_PORT;
	opts->middlebox	= 1;	/* enabled by default */
	opts->tls13		= 1;	/* enable TLS 1.3 */

	ft_getoptInit(&st, argc, argv);
	st.index = 0;

	while (1)
	{
		status = ft_getoptLong(&st, shortOpts, g_serverLongOpts);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_POSITIONAL)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: server: unexpected argument '%s'\n", st.argv[st.index]);
			return (0);
		}
		if (status == FT_GETOPT_ERROR)
		{
			if (st.status == FT_GETOPT_MISSING_ARG)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: server: option '%c' requires an argument\n", st.opt);
			else if (st.status == FT_GETOPT_AMBIGUOUS)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: server: ambiguous option '%s'\n", st.badOpt);
			else
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: server: invalid option '%s'\n", st.badOpt ? st.badOpt : "?");
			return (0);
		}

		if (status == FT_GETOPT_OK)
		{
			switch (st.opt)
			{
			case 'a': opts->passin   = st.optArg; break;
			case 'c': opts->certFile = st.optArg; break;
			case 'k': opts->keyFile  = st.optArg; break;
			case 'p': opts->port     = st.optArg; break;
			case 'A': opts->acceptAddr = st.optArg; break;
			case '2': opts->tls12 = 1; break;
			case '3': opts->tls13 = 1; break;
			case 'C': opts->cipherSuites   = st.optArg; break;
			case 'E': opts->ciphersuites   = st.optArg; break;
			case 'w': opts->www = 1; break;
			case 'W': opts->WWW = 1; break;
			case 'H': opts->http = 1; break;
			case 'B': opts->nbio = 1; break;
			case 'Y': opts->async = 1; break;
			case 'M': opts->middlebox = 1; break;
			case 'N': opts->middlebox = 0; break;
			case 'R': opts->curves = st.optArg; break;
			case 'O': opts->groups = st.optArg; break;
			case 'Z': opts->notickets = 1; break;
			case 'S': opts->sessout = st.optArg; break;
			case 'i': opts->sessin = st.optArg; break;
			case 'K': opts->keylogFile = st.optArg; break;
			case 'm': opts->msg = 1; break;
			case 'd': opts->debug = 1; break;
			case 's': opts->state = 1; break;
			case 't': opts->trace = 1; break;
			case 'T': opts->timeout = ft_atoi((char *)st.optArg); break;
			case 'P': opts->proxy = st.optArg; break;
			case 'U': opts->unixPath = st.optArg; break;
			case '4': opts->ipv4 = 1; opts->ipv6 = 0; break;
			case '6': opts->ipv6 = 1; opts->ipv4 = 0; break;
			case 'h': opts->help = 1; return 1;

			/* long-only options */
			case 0x202: opts->HTTP = 1; break;   /* --HTTP */
			default:
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: server: unhandled option '%c'\n", st.opt);
				return (0);
			}
		}
	}

	/* If --accept is given, parse host:port */
	if (opts->acceptAddr)
	{
		char *colon = ft_strchr(opts->acceptAddr, ':');
		if (!colon)
		{
			ft_dprintf(STDERR_FILENO,
				"ft_ssl: server: --accept requires host:port format\n");
			return (0);
		}
	}

	return (1);
}

static void sigHandler(int sig)
{
	(void)sig;
	g_server.running = 0;
}

static int createServSock(const t_serverOptions *opts)
{
	int					sock;
	struct sockaddr_in	addr4;
	struct sockaddr_in6	addr6;
	void				*addr_ptr;
	socklen_t			addr_len;
	int					domain;
	int					port;
	int					opt = 1;

	port = ft_atoi(opts->port);
	if (port <= 0 || port > 65535) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: server: invalid port '%s'\n", opts->port);
		return (-1);
	}

	if (opts->acceptAddr)
	{
		char *colon = ft_strchr(opts->acceptAddr, ':');
		char *host = ft_strndup(opts->acceptAddr, colon - opts->acceptAddr);
		port = ft_atoi(colon + 1);
		if (port <= 0 || port > 65535) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: server: invalid port in --accept\n");
			free(host);
			return (-1);
		}
		free(host);
	}

	if (opts->ipv6) {
		domain = AF_INET6;
		ft_bzero(&addr6, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		addr6.sin6_addr = in6addr_any;
		addr_ptr = &addr6;
		addr_len = sizeof(addr6);
	} else {
		domain = AF_INET;
		ft_bzero(&addr4, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(port);
		addr4.sin_addr.s_addr = INADDR_ANY;
		addr_ptr = &addr4;
		addr_len = sizeof(addr4);
	}

#ifdef _WIN32
	sock = socket(domain, SOCK_STREAM, 0);
#else
	sock = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#endif
	if (sock < 0) {
		perror("socket");
		return (-1);
	}
#ifdef _WIN32
	/* Put in non-blocking mode on Windows */
	if (set_nonblocking(sock) < 0) {
		perror("ioctlsocket");
		close(sock);
		return (-1);
	}
#endif
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		close(sock);
		return (-1);
	}

	if (bind(sock, (struct sockaddr *)addr_ptr, addr_len) < 0) {
		perror("bind");
		close(sock);
		return (-1);
	}

	if (listen(sock, DEFAULT_BACKLOG) < 0) {
		perror("listen");
		close(sock);
		return (-1);
	}

	return (sock);
}

static int epollAdd(int epollFd, int fd, uint32_t events, void *data)
{
	struct epoll_event ev;
	ev.events = events | EPOLLET;
	ev.data.ptr = data;
	if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		perror("epoll_ctl: add");
		return (-1);
	}
	return (0);
}

static int epollMod(int epollFd, int fd, uint32_t events, void *data)
{
	struct epoll_event ev;
	ev.events = events | EPOLLET;
	ev.data.ptr = data;
	if (epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &ev) < 0) {
		perror("epoll_ctl: mod");
		return (-1);
	}
	return (0);
}

static void cleanupClient(t_client *client)
{
	if (client->fd >= 0) {
		epoll_ctl(g_server.epollFd, EPOLL_CTL_DEL, client->fd, NULL);
		if (client->handshake_done)
			tlsShutdown(&client->tls);
		tlsFreeConnection(&client->tls);
		close(client->fd);
	}
	ft_bzero(client, sizeof(*client));
	client->fd = -1;
	client->state = CLIENT_STATE_DONE;
}

static t_client *find_free_client(void)
{
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (g_server.clients[i].state == CLIENT_STATE_DONE ||
			g_server.clients[i].fd < 0)
			return &g_server.clients[i];
	}
	return (NULL);
}

static void handleNewConn(void)
{
	struct sockaddr_storage	clientAddr;
	socklen_t				clientAddrLen = sizeof(clientAddr);
	t_client				*client;

	while (1) {
#if defined(__linux__)
		int fd = accept4(g_server.serverFd,
						 (struct sockaddr *)&clientAddr,
						 &clientAddrLen,
						 SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
		int fd = accept(g_server.serverFd,
						(struct sockaddr *)&clientAddr,
						&clientAddrLen);
		if (fd >= 0) {
#ifndef _WIN32
			fcntl(fd, F_SETFL, O_NONBLOCK | O_CLOEXEC);
#endif
		}
#endif
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("accept");
			break;
		}

#ifdef _WIN32
		set_nonblocking(fd);
#endif

		client = find_free_client();
		if (!client) {
			ft_printf("[Server] Max clients reached, rejecting connection\n");
			close(fd);
			continue;
		}

		ft_bzero(client, sizeof(*client));
		client->fd			= fd;
		client->lastActivity = time(NULL);
		client->state		= CLIENT_STATE_HANDSHAKE;

		if (epollAdd(g_server.epollFd, fd, EPOLLIN, client) < 0) {
			close(fd);
			client->state = CLIENT_STATE_DONE;
			continue;
		}

		ft_printf("[Server] New client fd=%d\n", fd);
		g_server.numClients++;
	}
}

static void handleClient(t_client *client, uint32_t events)
{
	int ret;

	switch (client->state) {
	case CLIENT_STATE_HANDSHAKE:
		if (!(events & (EPOLLIN | EPOLLOUT)))
			break;

		ret = tlsAccept(&client->tls, &g_server.config, client->fd);
		if (ret == TLS_SUCCESS) {
			if (g_debug_state)
				ft_printf("[Server fd=%d] Handshake complete\n", client->fd);
			client->handshake_done = 1;
			client->state = CLIENT_STATE_READY;
			epollMod(g_server.epollFd, client->fd, EPOLLIN, client);
		} else if (ret == TLS_ERR_WANT_READ)
			epollMod(g_server.epollFd, client->fd, EPOLLIN, client);
		else if (ret == TLS_ERR_WANT_WRITE)
			epollMod(g_server.epollFd, client->fd, EPOLLOUT, client);
		else {
			ft_printf("[Server fd=%d] Handshake failed\n", client->fd);
			cleanupClient(client);
		}
		break;

	case CLIENT_STATE_READY:
		if (events & EPOLLIN) {
			client->state = CLIENT_STATE_READ_HTTP;
			handleClient(client, events);
		}
		break;

	case CLIENT_STATE_READ_HTTP:
		if (events & EPOLLIN) {
			ret = tlsRead(&client->tls, client->buffer, BUFFER_SIZE - 1);
			if (ret > 0) {
				client->buffer[ret] = '\0';
				client->bufferLen = ret;
				if (g_debug_msg) {
					ft_printf("\n[Server fd=%d] HTTP request (%d bytes):\n",
							  client->fd, ret);
					write(STDOUT_FILENO, client->buffer, ret);
					ft_printf("\n");
				}
				client->state = CLIENT_STATE_SEND_RESPONSE;
				epollMod(g_server.epollFd, client->fd, EPOLLOUT, client);
			} else if (ret == TLS_ERR_WANT_READ) {
				/* stay */
			} else
				cleanupClient(client);
		}
		break;

	case CLIENT_STATE_SEND_RESPONSE:
		if (events & EPOLLOUT) {
			const char *response =
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/html\r\n"
				"Content-Length: 87\r\n"
				"Connection: close\r\n"
				"\r\n"
				"<html><body>\r\n"
				"<h1>TLS 1.3 Test Server</h1>\r\n"
				"<p>Connection established successfully!</p>\r\n"
				"</body></html>\r\n";

			ret = tlsWrite(&client->tls, (const uint8_t *)response,
						   ft_strlen(response));
			if (ret > 0) {
				client->state = CLIENT_STATE_CLOSING;
				epollMod(g_server.epollFd, client->fd, EPOLLIN, client);
			} else if (ret == TLS_ERR_WANT_WRITE) {
				/* stay */
			} else
				cleanupClient(client);
		}
		break;

	case CLIENT_STATE_CLOSING:
		if (client->handshake_done) {
			ret = tlsShutdown(&client->tls);
			if (ret == TLS_ERR_WANT_READ || ret == TLS_ERR_WANT_WRITE)
				break;
		}
		ft_printf("[Server fd=%d] Disconnected\n", client->fd);
		cleanupClient(client);
		g_server.numClients--;
		break;

	default:
		break;
	}
}

static void eventLoop(void)
{
	struct epoll_event events[MAX_EVENTS];

	while (g_server.running) {
		int n = epoll_wait(g_server.epollFd, events, MAX_EVENTS, 1000);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			break;
		}

		time_t now = time(NULL);
		for (int i = 0; i < n; i++) {
			void *ptr = events[i].data.ptr;

			if (ptr == &g_server.serverFd) {
				handleNewConn();
				continue;
			}

			t_client *client = (t_client *)ptr;
			uint32_t ev = events[i].events;

			if (ev & (EPOLLERR | EPOLLHUP)) {
				ft_printf("[Server fd=%d] Error/HUP\n", client->fd);
				cleanupClient(client);
				g_server.numClients--;
				continue;
			}

			client->lastActivity = now;
			handleClient(client, ev);

			if (g_server.opts.timeout > 0 &&
				now - client->lastActivity > g_server.opts.timeout) {
				ft_printf("[Server fd=%d] Timeout\n", client->fd);
				cleanupClient(client);
				g_server.numClients--;
			}
		}
	}
}

int cmdServer(int argc, char **argv, char **env)
{
	(void)env;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: server: WSAStartup failed\n");
		return (1);
	}
#endif

	ft_bzero(&g_server, sizeof(g_server));

	if (!parseServerArgs(argc - 2, argv + 2, &g_server.opts))
		return (1);

	if (g_server.opts.help) {
		printServerHelp();
		return (0);
	}

	if (!g_server.opts.certFile)
		g_server.opts.certFile = "certificate.crt";
	if (!g_server.opts.keyFile)
		g_server.opts.keyFile = "private.key";

	if (!tlsConfigInit(&g_server.config))
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: server: failed to init TLS config\n");
		return (1);
	}

	char *password = NULL;
	if (g_server.opts.passin)
	{
		password = getPassword(g_server.opts.passin, env);
		if (!password)
		{
			ft_dprintf(STDERR_FILENO, "ft_ssl: server: failed to get password\n");
			tlsConfigFree(&g_server.config);
			return (1);
		}
	}

	if (!tlsConfigLoadCertKey(&g_server.config, g_server.opts.certFile, g_server.opts.keyFile, password))
	{
		ft_dprintf(STDERR_FILENO, "ft_ssl: server: failed to load certificate/key\n");
		tlsConfigFree(&g_server.config);
		free(password);
		return (1);
	}
	if (password) {
		secureZeroMemory(password, ft_strlen(password));
		free(password);
	}

	if (g_server.opts.tls12 && g_server.opts.tls13)
		g_server.config.versionPref = TLS_VERSION_PREF_TLS13_AND_12;
	else if (g_server.opts.tls12)
		g_server.config.versionPref = TLS_VERSION_PREF_TLS12_ONLY;
	else
		g_server.config.versionPref = TLS_VERSION_PREF_TLS13_ONLY;

	if (g_server.opts.middlebox >= 0)
		g_server.config.middleboxCompat = g_server.opts.middlebox;

	g_debug_msg   = g_server.opts.msg   || g_server.opts.debug || g_server.opts.trace;
	g_debug_state = g_server.opts.state || g_server.opts.debug;
	g_debug_trace = g_server.opts.trace;

	g_server.serverFd = createServSock(&g_server.opts);
	if (g_server.serverFd < 0) {
		tlsConfigFree(&g_server.config);
		return (1);
	}

	ft_printf("[Server] Listening on port %s\n", g_server.opts.port);

	g_server.epollFd = epoll_create1(EPOLL_CLOEXEC);
	if (g_server.epollFd < 0) {
		perror("epoll_create1");
		close(g_server.serverFd);
		tlsConfigFree(&g_server.config);
		return (1);
	}

	if (epollAdd(g_server.epollFd, g_server.serverFd, EPOLLIN, &g_server.serverFd) < 0) {
		close(g_server.serverFd);
		close(g_server.epollFd);
		tlsConfigFree(&g_server.config);
		return (1);
	}

	for (int i = 0; i < MAX_CLIENTS; i++) {
		g_server.clients[i].fd = -1;
		g_server.clients[i].state = CLIENT_STATE_DONE;
	}

	signal(SIGINT,  sigHandler);
	signal(SIGTERM, sigHandler);
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	g_server.running = 1;
	ft_printf("[Server] Starting event loop\n");
	eventLoop();

	ft_printf("[Server] Shutting down...\n");
	for (size_t i = 0; i < MAX_CLIENTS; i++) {
		if (g_server.clients[i].fd >= 0)
			cleanupClient(&g_server.clients[i]);
	}
	close(g_server.serverFd);
	close(g_server.epollFd);
#ifdef _WIN32
	WSACleanup();
#endif
	tlsConfigFree(&g_server.config);
	ft_printf("[Server] Goodbye!\n");
	return (0);
}
