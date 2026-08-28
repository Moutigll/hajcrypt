#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/cipher/base64.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/utils/utils.h"
#include "../../includes/totp.h"
#include "../../includes/cli/password.h"

#include "../../includes/cli/totp.h"

static volatile sig_atomic_t g_running = 1;
static void sigintHandler(int sig) { (void)sig; g_running = 0; }

static const tFtLongOption g_longOpts[] = {
	{"secret",		FT_GETOPT_REQUIRED_ARGUMENT,	's'},
	{"algo",		FT_GETOPT_REQUIRED_ARGUMENT,	'a'},
	{"digits",		FT_GETOPT_REQUIRED_ARGUMENT,	'd'},
	{"period",		FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"user",		FT_GETOPT_REQUIRED_ARGUMENT,	'u'},
	{"issuer",		FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"uri",			FT_GETOPT_NO_ARGUMENT,			'U'},
	{"live",		FT_GETOPT_NO_ARGUMENT,			'l'},
	{"batch",		FT_GETOPT_NO_ARGUMENT,			'b'},
	{"show-secret",	FT_GETOPT_NO_ARGUMENT,			'S'},
	{"help",		FT_GETOPT_NO_ARGUMENT,			'h'},
	{NULL, 0, 0}
};

static void printTotpHelp(void)
{
	ft_printf(
		"Usage: ft_ssl totp [options] [uri]\n"
		"Generate Time‑based One‑Time Passwords (TOTP) as per RFC 6238.\n"
		"Options:\n"
		"  -s, --secret    <base32>   Secret key (Base32). If not provided, a random one is generated.\n"
		"  -a, --algo      <algo>     Hash algorithm: sha1, sha256, sha512 (default: sha1)\n"
		"  -d, --digits    <num>      Number of digits: 6 or 8 (default: 6)\n"
		"  -p, --period    <sec>      Time step in seconds (default: 30)\n"
		"  -u, --user      <email>    User identifier for URI (default: blahaj)\n"
		"  -i, --issuer    <name>     Issuer name for URI (default: hajcrypt)\n"
		"  -U, --uri                  Generate TOTP URI (using provided parameters) and exit\n"
		"  -l, --live                 Continuously refresh code (press Ctrl+C to exit)\n"
		"  -b, --batch                Non‑interactive mode; use defaults for missing values\n"
		"  -S, --show-secret          Also print the secret when generating URI\n"
		"  -h, --help                 Show this help\n"
		"\n"
		"  [uri]                       TOTP URI (otpauth://...) to use as source for code generation\n"
		"                              (mutually exclusive with -U)\n"
		"\n"
		"If no options are given and --batch is not set, you will be prompted interactively.\n"
		"The --live mode shows the current code and updates every second until interrupted.\n"
	);
}


static void promptString(const char *prompt, char *buf, size_t bufsize, const char *def)
{
	ft_printf("%s", prompt);
	if (def) ft_printf(" [%s]", def);
	ft_printf(": ");
	fflush(stdout);
	if (fgets(buf, bufsize, stdin) != NULL) {
		size_t len = ft_strlen(buf);
		if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
		if (len == 0 && def) ft_strlcpy(buf, def, bufsize);
	}
}

static void promptInt(const char *prompt, int *val, int def)
{
	char buf[32];
	ft_printf("%s [%d]: ", prompt, def);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) != NULL) {
		if (buf[0] == '\n') *val = def;
		else *val = ft_atoi(buf);
	} else {
		*val = def;
	}
}

static void interactiveFill(t_totpOpts *opts)
{
	char buf[256];
	char *secretBuf = NULL;

	if (!opts->secret) {
		secretBuf = promptPassword("Enter secret (Base32) or leave empty for random: ", 0);
		if (secretBuf && secretBuf[0] != '\0')
			opts->secret = secretBuf;
		else {
			free(secretBuf);
			opts->secret = NULL; /* will generate random later */
		}
	}

	if (!opts->algoName || !getHashByName(opts->algoName)) {
		promptString("Algorithm (sha1/sha256/sha512)", buf, sizeof(buf), "sha1");
		if (buf[0]) opts->algoName = ft_strdup(buf);
		else opts->algoName = "sha1";
	}

	if (opts->digits == 0) {
		int val;
		promptInt("Number of digits", &val, 6);
		opts->digits = val;
	}

	if (opts->period == 0) {
		int val;
		promptInt("Period (seconds)", &val, 30);
		opts->period = val;
	}

	if (!opts->user || ft_strcmp(opts->user, DEFAULT_USER) == 0) {
		promptString("User (email)", buf, sizeof(buf), DEFAULT_USER);
		if (buf[0]) opts->user = ft_strdup(buf);
		else opts->user = DEFAULT_USER;
	}

	if (!opts->issuer || ft_strcmp(opts->issuer, DEFAULT_ISSUER) == 0) {
		promptString("Issuer", buf, sizeof(buf), DEFAULT_ISSUER);
		if (buf[0]) opts->issuer = ft_strdup(buf);
		else opts->issuer = DEFAULT_ISSUER;
	}
}

static int parseTotpArgs(int argc, char **argv, t_totpOpts *opts)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts = "s:a:d:p:w:u:i:UlbSh";

	ft_bzero(opts, sizeof(t_totpOpts));
	opts->digits = DEFAULT_DIGITS;
	opts->period = DEFAULT_PERIOD;
	opts->user = DEFAULT_USER;
	opts->issuer = DEFAULT_ISSUER;
	opts->algoName = "sha1";

	if (argc == 0) return (1);

	ft_getoptInit(&st, argc, argv);
	while (1) {
		status = ft_getoptLong(&st, shortOpts, g_longOpts);
		if (status == FT_GETOPT_END) break;
		if (status == FT_GETOPT_POSITIONAL) {
			opts->uri = st.argv[st.index];
			st.index++;
			continue;
		}
		if (status == FT_GETOPT_ERROR) {
			if (st.status == FT_GETOPT_MISSING_ARG)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: totp: option '%s' requires an argument\n", st.badOpt);
			else if (st.status == FT_GETOPT_UNKNOWN)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: totp: unknown option '%s'\n", st.badOpt);
			else if (st.status == FT_GETOPT_AMBIGUOUS)
				ft_dprintf(STDERR_FILENO,
					"ft_ssl: totp: ambiguous option '%s' and '%s'\n", st.ambiguousA, st.ambiguousB);
			else
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: invalid option\n");
			return (0);
		}
		if (status == FT_GETOPT_OK) {
			switch (st.opt) {
				case 's': opts->secret = st.optArg; break;
				case 'a': opts->algoName = st.optArg; break;
				case 'd': opts->digits = ft_atoi(st.optArg); break;
				case 'p': opts->period = ft_atoi(st.optArg); break;
				case 'u': opts->user = st.optArg; break;
				case 'i': opts->issuer = st.optArg; break;
				case 'U': opts->generateUri = 1; break;
				case 'l': opts->live = 1; break;
				case 'b': opts->batch = 1; break;
				case 'S': opts->showSecret = 1; break;
				case 'h': printTotpHelp(); return -1;
				default: break;
			}
			continue;
		}
	}

	if (st.index < st.argc) {
		const char *pos = st.argv[st.index];
		if (ft_strncmp(pos, "otpauth://", 10) == 0)
			opts->uri = pos;
		else if (!opts->secret)
			opts->secret = pos;
		else
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: extra argument '%s' ignored\n", pos);
	}

	/* validation */
	if (opts->digits != 6 && opts->digits != 8) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: digits must be 6 or 8\n");
		return (0);
	}
	if (opts->period <= 0) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: period must be > 0\n");
		return (0);
	}
	if (opts->algoName && !getHashByName(opts->algoName)) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: unknown algorithm '%s'\n", opts->algoName);
		return (0);
	}
	return (1);
}

/* ---------- clipboard, terminal & mouse helpers ---------- */

static void copyToClipboard(const char *text)
{
	int copied = 0;

#ifdef __linux__
	/* Try native Wayland or X11 tools */
	const char *display = getenv("WAYLAND_DISPLAY");
	char cmd[512];
	int ret;
	if (display && display[0] != '\0')
		ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | wl-copy 2>/dev/null", text);
	else
		ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | xclip -selection clipboard 2>/dev/null", text);
	ret = system(cmd);
	if (ret == 0) copied = 1;
#elif __APPLE__
	char cmd[512];
	ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | pbcopy", text);
	if (system(cmd) == 0) copied = 1;
#elif _WIN32
	if (OpenClipboard(NULL)) {
		EmptyClipboard();
		size_t len = strlen(text) + 1;
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
		if (hMem) {
			memcpy(GlobalLock(hMem), text, len);
			GlobalUnlock(hMem);
			SetClipboardData(CF_TEXT, hMem);
		}
		CloseClipboard();
		copied = 1;
	}
#endif

	/* Fallback: OSC 52 if supported by terminal */
	if (!copied) {
		char b64[512];
		int ret = base64Encode((const unsigned char *)text, strlen(text), b64, sizeof(b64));
		if (ret > 0) {
			ft_printf("\033]52;c;%s\007", b64);
			fflush(stdout);
		}
	}
}

/* --- Terminal raw mode helpers (Unix/Linux only) --- */
#ifndef _WIN32

static struct termios g_origTermios;
static int g_termiosSaved = 0;

static void disableRawMode(void)
{
	if (g_termiosSaved)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_origTermios);
}

static void enableRawMode(void)
{
	struct termios raw;

	if (tcgetattr(STDIN_FILENO, &g_origTermios) == -1)
		return;
	g_termiosSaved = 1;
	atexit(disableRawMode);
	raw = g_origTermios;
	raw.c_lflag &= ~(ICANON | ECHO);
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static char readInputEvent(void)
{
	char c;

	if (read(STDIN_FILENO, &c, 1) != 1)
		return (0);

	if (c != '\033')
		return (c);

	char c2;
	if (read(STDIN_FILENO, &c2, 1) != 1 || c2 != '[')
		return (0);

	char c3;
	if (read(STDIN_FILENO, &c3, 1) != 1)
		return (0);

	if (c3 == '<') {
		char buf[32];
		int  i = 0;
		char ch;

		while (i < (int)sizeof(buf) - 1 && read(STDIN_FILENO, &ch, 1) == 1) {
			if (ch == 'M' || ch == 'm') {
				int btn, x, y;
				buf[i] = '\0';
				if (sscanf(buf, "%d;%d;%d", &btn, &x, &y) == 3
					&& ch == 'M' && btn == 0)
					return ('M');
				return (0);
			}
			buf[i++] = ch;
		}
		return (0);
	}

	return (0);
}

#endif

static void enableMouseTracking(void)
{
#ifndef _WIN32
	ft_printf("\033[?1000h");
	ft_printf("\033[?1006h");
	fflush(stdout);
#endif
}

static void disableMouseTracking(void)
{
#ifndef _WIN32
	ft_printf("\033[?1006l");
	ft_printf("\033[?1000l");
	fflush(stdout);
#endif
}

/* ---------- Main command ---------- */

int cmdTotp(int argc, char **argv, char **env)
{
	t_totpOpts		opts;
	int				ret;
	const t_hash	*algo;
	char			secretBuf[128];
	char			code[16];
	t_totpCtx		ctx;
	t_totpConfig	config;
	char			uri[512];
	int				first = 1;

	(void)env;

	if (argc == 2) {
		ft_bzero(&opts, sizeof(opts));
		opts.digits = DEFAULT_DIGITS;
		opts.period = DEFAULT_PERIOD;
		opts.window = DEFAULT_WINDOW;
		opts.user = DEFAULT_USER;
		opts.issuer = DEFAULT_ISSUER;
		opts.algoName = "sha1";
	} else {
		ret = parseTotpArgs(argc - 1, argv + 1, &opts);
		if (ret < 0) return (0);   /* help */
		if (ret == 0) return (1);
	}

	if (opts.generateUri) {
		if (!opts.batch && (!opts.secret || !opts.user || !opts.issuer)) {
			interactiveFill(&opts);
		}
		algo = getHashByName(opts.algoName);
		if (!opts.secret) {
			if (totpGenerateSecret(algo, secretBuf, sizeof(secretBuf)) != 0) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to generate secret\n");
				return (1);
			}
			opts.secret = secretBuf;
			ft_printf("Generated secret: %s\n", secretBuf);
		}
		config.algo = algo;
		config.digits = opts.digits;
		config.period = opts.period;
		config.window = opts.window;
		if (totpInitWithConfig(&ctx, opts.secret, &config) != 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: invalid secret or configuration\n");
			return (1);
		}
		if (totpCreateUri(opts.user, opts.secret, opts.issuer, &ctx.config,
						  uri, sizeof(uri)) != 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to create URI\n");
			return (1);
		}
		ft_printf("%s\n", uri);
		if (opts.showSecret)
			ft_printf("Secret: %s\n", opts.secret);
		return (0);
	}

	if (opts.uri) {
		if (totpInitFromUri(&ctx, opts.uri) != 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: invalid URI\n");
			return (1);
		}
		algo = getHashByName(opts.algoName);
		if (algo) ctx.config.algo = algo;
		if (opts.digits != 0) ctx.config.digits = opts.digits;
		if (opts.period != 0) ctx.config.period = opts.period;
		if (opts.window != 0) ctx.config.window = opts.window;
		goto generation;
	}

	algo = getHashByName(opts.algoName);

	if (!opts.batch) {
		if (!opts.secret || !opts.user || !opts.issuer) {
			interactiveFill(&opts);
			algo = getHashByName(opts.algoName);
		}
	}

	if (!opts.secret) {
		if (totpGenerateSecret(algo, secretBuf, sizeof(secretBuf)) != 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to generate secret\n");
			return (1);
		}
		opts.secret = secretBuf;
		ft_printf("Generated secret: %s\n", secretBuf);
	}

	config.algo = algo;
	config.digits = opts.digits;
	config.period = opts.period;
	config.window = opts.window;

	if (totpInitWithConfig(&ctx, opts.secret, &config) != 0) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: invalid secret or configuration\n");
		return (1);
	}

generation:
	if (opts.live) {
		signal(SIGINT, sigintHandler);

#ifndef _WIN32
		enableRawMode();
#endif
		enableMouseTracking();

		uint64_t now = (uint64_t)time(NULL);
		long remaining;
		static char prev_code[16] = "";
		char c = 0;

		while (g_running) {
			now = (uint64_t)time(NULL);
			if (totpGenerate(&ctx, now, code) != 0) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: generation error\n");
				disableMouseTracking();
#ifndef _WIN32
				disableRawMode();
#endif
				return (1);
			}
			remaining = (long)(ctx.config.period - (now % ctx.config.period));

			/* Update display */
			if (!first) {
				if (ft_strcmp(code, prev_code) != 0) {
					ft_printf("\r%s  (expires in %2lds)  [Click to copy]  [Ctrl+C to exit]",
					          code, remaining);
					ft_strlcpy(prev_code, code, sizeof(prev_code));
				} else {
					int col = ft_strlen(code) + 15;
					ft_printf("\033[%dG%2lds", col, remaining);
				}
			} else {
				ft_printf("%s  (expires in %2lds)  [Click to copy]  [Ctrl+C to exit]",
				          code, remaining);
				ft_strlcpy(prev_code, code, sizeof(prev_code));
				first = 0;
			}
			fflush(stdout);

#ifndef _WIN32
			/* Wait 1 second or until a key is pressed (Unix) */
			fd_set fds;
			struct timeval tv = {1, 0};
			FD_ZERO(&fds);
			FD_SET(STDIN_FILENO, &fds);
			int sel = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);

			if (sel > 0) {
				c = readInputEvent();
				if (c == 'c' || c == 'C' || c == 'M') {
					copyToClipboard(code);
					ft_printf("\r%s  (expires in %2lds)  [\u2713 Copied!]  [Ctrl+C to exit]",
					          code, remaining);
					fflush(stdout);
					sleep(1);
				} else if (c == 'q' || c == 'Q') {
					g_running = 0;
					break;
				}
			}
#else
			/* Windows version */
			Sleep(1000);
			if (_kbhit()) {
				c = _getch();
				if (c == 'c' || c == 'C') {
					copyToClipboard(code);
					ft_printf("\r%s  (expires in %2lds)  [Copied!]  [Ctrl+C to exit]",
					          code, remaining);
					fflush(stdout);
					Sleep(1000);
				} else if (c == 'q' || c == 'Q') {
					g_running = 0;
					break;
				}
			}
#endif
		}

		disableMouseTracking();
#ifndef _WIN32
		disableRawMode();
#endif
		ft_printf("\n");
		secureZeroMemory(code, sizeof(code));
		secureZeroMemory(secretBuf, sizeof(secretBuf));
		return (0);
	}

	uint64_t now = (uint64_t)time(NULL);
	if (totpGenerate(&ctx, now, code) != 0) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: generation error\n");
		return (1);
	}
	ft_printf("%s\n", code);
	secureZeroMemory(code, sizeof(code));
	secureZeroMemory(secretBuf, sizeof(secretBuf));
	return (0);
}
