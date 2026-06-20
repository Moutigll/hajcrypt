#ifndef CLI_TLS_H
#define CLI_TLS_H

#include "../../tls/includes/btls.h"

#define DEFAULT_PORT	"4433"
#define DEFAULT_BACKLOG	128
#define MAX_EVENTS		64
#define MAX_CLIENTS		1024
#define BUFFER_SIZE		4096
#define IDLE_TIMEOUT	300


typedef enum {
	CLIENT_STATE_NEW,
	CLIENT_STATE_HANDSHAKE,
	CLIENT_STATE_READY,
	CLIENT_STATE_READ_HTTP,
	CLIENT_STATE_SEND_RESPONSE,
	CLIENT_STATE_CLOSING,
	CLIENT_STATE_DONE
} t_client_state;


typedef struct s_serverOptions
{
	const char	*certFile;
	const char	*keyFile;
	const char	*passin;
	const char	*port;
	const char	*acceptAddr;
	int			tls12;
	int			tls13;
	const char	*cipherSuites;
	const char	*ciphersuites;
	int			www;
	int			WWW;
	int			HTTP;
	int			http;
	int			nbio;
	int			async;
	int			middlebox;
	const char	*curves;
	const char	*groups;
	int			notickets;
	const char	*sessout;
	const char	*sessin;
	const char	*keylogFile;
	int			msg;
	int			debug;
	int			state;
	int			trace;
	int			timeout;
	const char	*proxy;
	const char	*unixPath;
	int			ipv4;
	int			ipv6;
	int			help;
} t_serverOptions;

typedef struct {
	int				fd;
	t_tlsCtx		tls;
	t_client_state	state;
	uint8_t			buffer[BUFFER_SIZE];
	size_t			bufferLen;
	int				handshake_done;
	time_t			lastActivity;
} t_client;

typedef struct {
	int				epollFd;
	int				serverFd;
	t_client		clients[MAX_CLIENTS];
	size_t			numCLients;
	t_tlsConfig		config;
	t_serverOptions	opts;
	int				running;
} t_server;

int cmdServer(int argc, char **argv, char **env);

#endif /* CLI_TLS_H */
