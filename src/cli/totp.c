// totp.c
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>

#ifdef _WIN32
	#include <windows.h>
	#include <conio.h>
	#include <direct.h>
	#include <io.h>
	#define PATH_MAX 260
	#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
	#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#else
	#include <sys/stat.h>
	#include <sys/select.h>
	#include <dirent.h>
	#include <termios.h>
	#include <unistd.h>
#endif

#include "../../hajlib/include/hajlib.h" /* IWYU pragma: keep */
#include "../../includes/cipher/base32.h"
#include "../../includes/cipher/base64.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/utils/utils.h"
#include "../../includes/totp.h"
#include "../../includes/cli/password.h"
#include "../../includes/cli/totp.h"

static volatile sig_atomic_t g_running = 1;
static void sigintHandler(int sig) { (void)sig; g_running = 0; }

static const tFtLongOption g_totpLongOpts[] = {
	{"secret",		FT_GETOPT_REQUIRED_ARGUMENT,	's'},
	{"input",		FT_GETOPT_REQUIRED_ARGUMENT,	'i'},
	{"output",		FT_GETOPT_REQUIRED_ARGUMENT,	'o'},
	{"passin",		FT_GETOPT_REQUIRED_ARGUMENT,	'p'},
	{"passout",		FT_GETOPT_REQUIRED_ARGUMENT,	'P'},
	{"algo",		FT_GETOPT_REQUIRED_ARGUMENT,	'a'},
	{"digits",		FT_GETOPT_REQUIRED_ARGUMENT,	'd'},
	{"period",		FT_GETOPT_REQUIRED_ARGUMENT,	't'},
	{"user",		FT_GETOPT_REQUIRED_ARGUMENT,	'u'},
	{"issuer",		FT_GETOPT_REQUIRED_ARGUMENT,	'I'},
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
		"Usage: ft_ssl totp [options] [uri...]\n"
		"Generate Time‑based One‑Time Passwords (TOTP) as per RFC 6238.\n"
		"Options:\n"
		"  -s, --secret    <base32>          Secret key (Base32). Can be repeated.\n"
		"  -i, --input     <file/directory>  Read secrets from file(s) or directory.\n"
		"  -o, --output    <file>            Output file. If extension .totp, saves encrypted store.\n"
		"  -p, --passin    <password>        Input password for encrypted files.\n"
		"  -P, --passout   <password>        Output password for encrypted store.\n"
		"      --*                           Any supported cipher (e.g., --des, --aes256-cbc).\n"
		"  -a, --algo      <algo>            Hash: sha1, sha256, sha512 (default: sha1).\n"
		"  -d, --digits    <num>             6 or 8 digits (default: 6).\n"
		"  -t, --period    <sec>             Time step (default: 30).\n"
		"  -u, --user      <email>           Default user label (default: blahaj).\n"
		"  -I, --issuer    <name>            Default issuer (default: hajcrypt).\n"
		"  -U, --uri                         Generate TOTP URIs instead of codes.\n"
		"  -l, --live                        Live mode: refresh codes every second.\n"
		"  -b, --batch                       Non‑interactive; use defaults.\n"
		"  -S, --show-secret                 Print the secret when generating URIs.\n"
		"  -h, --help                        Show this help.\n"
		"\n"
		"Positional URIs (otpauth://...) are also accepted.\n"
		"In live mode, click a code to copy it to the clipboard.\n"
	);
}

static int addToArray(char ***arr, int *count, const char *str)
{
	char *copy = ft_strdup(str);
	if (!copy)
		return (0);
	*arr = realloc(*arr, (*count + 2) * sizeof(char *));
	if (!*arr) {
		free(copy);
		return (0);
	}
	(*arr)[*count] = copy;
	(*arr)[++*count] = NULL;
	return (1);
}

static void freeStringArray(char ***arr, int *count)
{
	if (!arr || !*arr)
		return;
	for (int i = 0; i < *count; i++)
		free((*arr)[i]);
	free(*arr);
	*arr = NULL;
	*count = 0;
}

static int createEntryFromSecret(const char		*secretBase32,
								 const t_hash	*algo,
								 int			digits,
								 uint32_t		period,
								 const char		*user,
								 const char		*issuer,
								 t_totpEntry	*entry)
{
	ft_bzero(entry, sizeof(t_totpEntry));
	entry->algo = algo;
	entry->digits = (uint8_t)digits;
	entry->period = period;
	entry->window = 1;

	size_t len = base32Decode(secretBase32, entry->secret, sizeof(entry->secret));
	if (len == (size_t)-1 || len == 0)
		return (0);
	entry->secretLen = len;

	entry->label = user ? ft_strdup(user) : ft_strdup(DEFAULT_USER);
	if (!entry->label)
		return (0);
	entry->issuer = issuer ? ft_strdup(issuer) : ft_strdup(DEFAULT_ISSUER);
	if (!entry->issuer) {
		free(entry->label);
		return (0);
	}
	return (1);
}

static int loadStoreFromFile(const char *path, t_totpEntry **entries, size_t *count, const char *passin, int batch)
{
	char		*pem = NULL;
	size_t		pemLen = 0;
	t_totpStore	store = {0};
	int			loaded = 0;
	int			isEncrypted;

	readBinaryFile(path, (uint8_t **)&pem, &pemLen);
	if (!pem)
		return (0);
	pem[pemLen] = '\0';

	isEncrypted = (ft_strstr(pem, "-----BEGIN ENCRYPTED TOTP-----") != NULL);

	if (isEncrypted) {
		if (passin && *passin) {
			if (totpStoreFromPem(pem, passin, &store) == 1)
				loaded = 1;
			else
				HAJCRYPT_DPRINT("loadStoreFromFile: decryption with provided password failed\n");
		}

		if (!loaded && !batch) {
			/* Reset store before second attempt */
			ft_bzero(&store, sizeof(store));
			char *prompt = ft_strjoin("Enter password to decrypt '", path);
			char *fullPrompt = ft_strjoin_free(prompt, "': ", 1, 0);
			char *pass = promptPassword(fullPrompt, 0);
			free(fullPrompt);
			if (pass) {
				if (totpStoreFromPem(pem, pass, &store) == 1)
					loaded = 1;
				else
					HAJCRYPT_DPRINT("loadStoreFromFile: decryption with prompt password failed\n");
				secureZeroMemory(pass, ft_strlen(pass));
				free(pass);
			}
		}
	} else {
		if (totpStoreFromPem(pem, NULL, &store) == 1)
			loaded = 1;
		else
			HAJCRYPT_DPRINT("loadStoreFromFile: failed to load unencrypted store\n");
	}

	free(pem);
	if (!loaded)
		return (0);

	if (store.count > 0) {
		size_t newCount = *count + store.count;
		t_totpEntry *newArr = realloc(*entries, newCount * sizeof(t_totpEntry));
		if (!newArr) {
			for (size_t i = 0; i < store.count; i++) {
				free(store.entries[i].label);
				free(store.entries[i].issuer);
			}
			free(store.entries);
			return (0);
		}
		*entries = newArr;
		for (size_t i = 0; i < store.count; i++) {
			(*entries)[*count + i] = store.entries[i];
		}
		*count = newCount;
		free(store.entries);
		store.entries = NULL;
		store.count = 0;
	}
	return (1);
}

static void scanDirectory(const char *path, t_totpEntry **entries, size_t *count, const char *passin, int batch)
{
#ifdef _WIN32
	WIN32_FIND_DATA findData;
	HANDLE hFind;
	char searchPath[PATH_MAX];
	char fullPath[PATH_MAX];

	ft_snprintf(searchPath, sizeof(searchPath), "%s\\*", path);
	hFind = FindFirstFile(searchPath, &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cannot open directory '%s'\n", path);
		return;
	}

	do {
		if (ft_strcmp(findData.cFileName, ".") == 0 ||
			ft_strcmp(findData.cFileName, "..") == 0)
			continue;
		if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			const char *ext = ft_strrchr(findData.cFileName, '.');
			if (ext && ft_strcmp(ext, ".totp") == 0) {
				ft_snprintf(fullPath, sizeof(fullPath), "%s\\%s", path, findData.cFileName);
				loadStoreFromFile(fullPath, entries, count, passin, batch);
			}
		}
	} while (FindNextFile(hFind, &findData));

	FindClose(hFind);
#else
	DIR *dir = opendir(path);
	if (!dir) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cannot open directory '%s'\n", path);
		return;
	}

	struct dirent *ent;
	char fullPath[PATH_MAX];
	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_type == DT_REG) {
			const char *ext = ft_strrchr(ent->d_name, '.');
			if (ext && ft_strcmp(ext, ".totp") == 0) {
				ft_snprintf(fullPath, sizeof(fullPath), "%s/%s", path, ent->d_name);
				loadStoreFromFile(fullPath, entries, count, passin, batch);
			}
		}
	}
	closedir(dir);
#endif
}

static int getFileStat(const char *path, struct stat *st)
{
#ifdef _WIN32
	struct _stat winStat;
	if (_stat(path, &winStat) != 0)
		return (-1);
	st->st_mode = winStat.st_mode;
	st->st_size = winStat.st_size;
	st->st_mtime = winStat.st_mtime;
	return (0);
#else
	return (stat(path, st));
#endif
}

static int parseTotpArgs(int argc, char **argv, t_totpOpts *opts)
{
	tFtGetopt		st;
	tFtGetoptStatus	status;
	const char		*shortOpts = "s:i:o:p:P:a:d:t:u:I:UlSbh";
	const t_cipher	*cipher;

	ft_bzero(opts, sizeof(t_totpOpts));
	opts->digits = DEFAULT_DIGITS;
	opts->period = DEFAULT_PERIOD;
	opts->window = DEFAULT_WINDOW;
	opts->user = DEFAULT_USER;
	opts->issuer = DEFAULT_ISSUER;
	opts->algoName = "sha1";

	ft_getoptInit(&st, argc, argv);
	while (1) {
		status = ft_getoptLong(&st, shortOpts, g_totpLongOpts);
		if (status == FT_GETOPT_END)
			break;
		if (status == FT_GETOPT_POSITIONAL) {
			const char *arg = st.argv[st.index];
			if (ft_strncmp(arg, "otpauth://", 10) == 0) {
				if (!addToArray(&opts->uris, &opts->uriCount, arg))
					return (0);
			} else {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: ignoring positional '%s'\n", arg);
			}
			st.index++;
			continue;
		}
		if (status == FT_GETOPT_ERROR) {
			if (st.status == FT_GETOPT_UNKNOWN && st.badOpt &&
				st.badOpt[0] == '-' && st.badOpt[1] == '-') {
				cipher = getCipherByName(st.badOpt + 2);
				if (cipher) {
					opts->cipher = cipher;
					st.index++;
					continue;
				}
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: unknown option/cipher '%s'\n", st.badOpt + 2);
			} else if (st.status == FT_GETOPT_MISSING_ARG) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: option '%c' requires an argument\n", st.opt);
			} else if (st.status == FT_GETOPT_AMBIGUOUS) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: ambiguous option '%s'\n", st.badOpt);
			} else {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: invalid option\n");
			}
			return (0);
		}
		if (status == FT_GETOPT_OK) {
			switch (st.opt) {
				case 's': addToArray(&opts->secrets, &opts->secretCount, st.optArg); break;
				case 'i': addToArray(&opts->inputFiles, &opts->inputCount, st.optArg); break;
				case 'o': opts->outputFile = st.optArg; break;
				case 'p': opts->passin = st.optArg; break;
				case 'P': opts->passout = st.optArg; break;
				case 'a': opts->algoName = st.optArg; break;
				case 'd': opts->digits = ft_atoi(st.optArg); break;
				case 't': opts->period = ft_atoi(st.optArg); break;
				case 'u': opts->user = st.optArg; break;
				case 'I': opts->issuer = st.optArg; break;
				case 'U': opts->generateUris = 1; break;
				case 'l': opts->live = 1; break;
				case 'b': opts->batch = 1; break;
				case 'S': opts->showSecret = 1; break;
				case 'h': printTotpHelp(); return (0);
				default: return (0);
			}
		}
	}

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

static void freeTotpOpts(t_totpOpts *opts)
{
	if (!opts)
		return;
	freeStringArray(&opts->secrets, &opts->secretCount);
	freeStringArray(&opts->inputFiles, &opts->inputCount);
	freeStringArray(&opts->uris, &opts->uriCount);
	ft_bzero(opts, sizeof(t_totpOpts));
}

static int buildEntries(t_totpOpts *opts, const char *passin, t_totpEntry **entries, size_t *count)
{
	const t_hash *algo = getHashByName(opts->algoName);
	if (!algo)
		algo = DEFAULT_ALGO;

	*entries = NULL;
	*count = 0;

	/* 1. From URIs */
	for (int i = 0; i < opts->uriCount; i++) {
		t_totpEntry e;
		if (totpInitFromUri(&e, opts->uris[i]) == 0) {
			e.window = opts->window;
			t_totpEntry *newArr = realloc(*entries, (*count + 1) * sizeof(t_totpEntry));
			if (!newArr) {
				free(e.label);
				free(e.issuer);
				return (0);
			}
			*entries = newArr;
			(*entries)[*count] = e;
			(*count)++;
		}
	}

	/* 2. From -s secrets */
	for (int i = 0; i < opts->secretCount; i++) {
		t_totpEntry e;
		if (createEntryFromSecret(opts->secrets[i], algo,
					opts->digits, opts->period,
					opts->user, opts->issuer, &e)) {
			t_totpEntry *newArr = realloc(*entries, (*count + 1) * sizeof(t_totpEntry));
			if (!newArr) {
				free(e.label);
				free(e.issuer);
				return (0);
			}
			*entries = newArr;
			(*entries)[*count] = e;
			(*count)++;
		}
	}

	/* 3. From -i files/dirs */
	for (int i = 0; i < opts->inputCount; i++) {
		const char *path = opts->inputFiles[i];
		struct stat st;
		if (getFileStat(path, &st) != 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cannot access '%s'\n", path);
			continue;
		}
		if (S_ISDIR(st.st_mode))
			scanDirectory(path, entries, count, passin, opts->batch);
		else if (S_ISREG(st.st_mode)) {
			if (!loadStoreFromFile(path, entries, count, passin, opts->batch))
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to load '%s'\n", path);
		}
	}

	/* Fallback interactive or batch */
	if (*count == 0 && !opts->batch && !opts->uriCount &&
		!opts->secretCount && !opts->inputCount) {
		ft_printf("Enter secret (Base32): ");
		char *secret = getNextLine(STDIN_FILENO);
		if (!secret) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to read secret\n");
			return (0);
		}
		secret = ft_strtrim(secret, "\r\n");
		if (secret && secret[0]) {
			t_totpEntry e;
			if (createEntryFromSecret(secret, algo, opts->digits, opts->period,
						opts->user, opts->issuer, &e)) {
				*entries = malloc(sizeof(t_totpEntry));
				if (*entries) {
					(*entries)[0] = e;
					*count = 1;
				} else {
					free(e.label);
					free(e.issuer);
				}
			}
		}
		free(secret);
	}
	if (*count == 0 && opts->batch && !opts->uriCount &&
		!opts->secretCount && !opts->inputCount) {
		char secret[64];
		if (totpGenerateSecret(algo, secret, sizeof(secret)) == 0) {
			t_totpEntry e;
			if (createEntryFromSecret(secret, algo, opts->digits, opts->period,
						opts->user, opts->issuer, &e)) {
				*entries = malloc(sizeof(t_totpEntry));
				if (*entries) {
					(*entries)[0] = e;
					*count = 1;
				} else {
					free(e.label);
					free(e.issuer);
				}
			}
		}
	}
	return (*count > 0);
}

static void copyToClipboard(const char *text)
{
	int copied = 0;

#ifdef __linux__
	const char	*display = getenv("WAYLAND_DISPLAY");
	char		cmd[512];
	if (display && display[0] != '\0')
		ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | wl-copy 2>/dev/null", text);
	else
		ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | xclip -selection clipboard 2>/dev/null", text);
	if (system(cmd) == 0)
		copied = 1;
#elif __APPLE__
	char cmd[512];
	ft_snprintf(cmd, sizeof(cmd), "echo -n '%s' | pbcopy", text);
	if (system(cmd) == 0)
		copied = 1;
#elif _WIN32
	if (OpenClipboard(NULL)) {
		EmptyClipboard();
		size_t len = ft_strlen(text) + 1;
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
		if (hMem) {
			ft_memcpy(GlobalLock(hMem), text, len);
			GlobalUnlock(hMem);
			SetClipboardData(CF_TEXT, hMem);
		}
		CloseClipboard();
		copied = 1;
	}
#endif

	if (!copied) {
		char b64[512];
		if (base64Encode((const unsigned char *)text, ft_strlen(text), b64, sizeof(b64)) > 0) {
			ft_printf("\033]52;c;%s\007", b64);
			fflush(stdout);
		}
	}
}

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


#endif

static void enableMouseTracking(void)
{
#ifndef _WIN32
	ft_printf("\033[?1000h\033[?1006h");
	fflush(stdout);
#endif
}

static void disableMouseTracking(void)
{
#ifndef _WIN32
	ft_printf("\033[?1006l\033[?1000l");
	fflush(stdout);
#endif
}

static void runLiveMode(t_totpEntry *entries, size_t count)
{
	if (count == 0)
		return;

	char	**prevCodes;
	int		*prevRemaining;
	int		first;
	int		instrRow;

	signal(SIGINT, sigintHandler);

	prevCodes = calloc(count, sizeof(char *));
	prevRemaining = calloc(count, sizeof(int));
	if (!prevCodes || !prevRemaining)
	{
		free(prevCodes);
		free(prevRemaining);
		return;
	}

#ifndef _WIN32
	enableRawMode();
#endif
	enableMouseTracking();

	first = 1;

	while (g_running)
	{
		uint64_t now = (uint64_t)time(NULL);

		/* Clear screen and move cursor home */
		if (!first)
			ft_printf("\033[H");
		else
		{
			ft_printf("\033[2J\033[H");
			first = 0;
		}

		/* Display each entry on a single line */
		for (size_t i = 0; i < count; i++)
		{
			t_totpEntry	*entry;
			char		code[16];
			int			ret;
			int			remaining;
			int			row;
			int			col;
			char		label[32];

			entry = &entries[i];

			/* Generate TOTP code */
			ret = totpGenerate(entry, now, code);
			if (ret != 0)
				ft_strlcpy(code, "ERROR", 16);

			/* Ensure period is valid */
			if (entry->period == 0)
				entry->period = DEFAULT_PERIOD;

			/* Calculate remaining time */
			remaining = (int)(entry->period - (now % entry->period));
			if (remaining < 0)
				remaining += entry->period;

			/* Position: one line per entry, no gaps */
			row = i + 1;
			col = 1;
			ft_printf("\033[%d;%dH", row, col);

			/* Format label */
			if (entry->issuer && entry->label)
				ft_snprintf(label, sizeof(label), "%s:%s",
						entry->issuer, entry->label);
			else if (entry->issuer)
				ft_strlcpy(label, entry->issuer, sizeof(label));
			else if (entry->label)
				ft_strlcpy(label, entry->label, sizeof(label));
			else
				ft_strlcpy(label, "?", sizeof(label));

			/* Display entry on a single line */
			ft_printf("%-30s %-10s  (%3ds)", label, code, remaining);

			/* Save current code for click detection */
			if (prevCodes[i])
				free(prevCodes[i]);
			prevCodes[i] = ft_strdup(code);
			prevRemaining[i] = remaining;
		}

		/* Display instructions at the bottom */
		instrRow = count + 1;
		ft_printf("\033[%d;1H", instrRow);
		ft_printf("Click a code to copy it. Press 'q' or Ctrl+C to exit.");
		ft_printf("\033[J"); /* Clear from cursor to end of screen */
		fflush(stdout);

#ifndef _WIN32
		/* Handle keyboard and mouse input */
		fd_set fds;
		struct timeval tv = {1, 0};
		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO, &fds);

		if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0)
		{
			char c;
			if (read(STDIN_FILENO, &c, 1) == 1)
			{
				if (c == 'q' || c == 'Q')
				{
					g_running = 0;
				}
				else if (c == '\033')
				{
					/* Parse mouse event (SGR format: ESC [ < btn ; x ; y M) */
					char buf[32];
					int i = 0;
					buf[i++] = c;

					while (i < (int)sizeof(buf) - 1 &&
							read(STDIN_FILENO, &buf[i], 1) == 1)
					{
						if (buf[i] == 'M' || buf[i] == 'm')
						{
							buf[i + 1] = '\0';
							int x, y, btn;
							char *p = ft_strchr(buf, '<');

							if (p && sscanf(p + 1, "%d;%d;%d", &btn, &x, &y) == 3)
							{
								int idx = -1;

								/* Find which entry was clicked */
								for (size_t j = 0; j < count; j++)
								{
									int row = j;
									int col = 1;
									if (y >= row && y <= row + 1 &&
										x >= col && x <= col + 50)
									{
										idx = j;
										break;
									}
								}

								/* Copy the clicked code to clipboard */
								if (idx >= 0 && idx < (int)count && prevCodes[idx])
								{
									copyToClipboard(prevCodes[idx]);
									ft_printf("\033[%d;1HCopied: %s",
											instrRow + 1, prevCodes[idx]);
									fflush(stdout);
									sleep(1);
								}
							}
							break;
						}
						i++;
					}
				}
			}
		}
#else
		/* Windows specific input handling */
		Sleep(1000);
		if (_kbhit())
		{
			char c = _getch();
			if (c == 'q' || c == 'Q')
				g_running = 0;
		}
#endif
	}

	/* Cleanup */
	disableMouseTracking();
#ifndef _WIN32
	disableRawMode();
#endif

	for (size_t i = 0; i < count; i++)
		free(prevCodes[i]);
	free(prevCodes);
	free(prevRemaining);

	ft_printf("\n");
}

int cmdTotp(int argc, char **argv, char **env)
{
	t_totpOpts	opts;
	int			ret = 0;
	char		*passinPass = NULL;
	char		*passoutPass = NULL;

	if (argc < 2) {
		ft_dprintf(STDERR_FILENO, "Usage: ft_ssl totp [options] [uri...]\n");
		return (1);
	}

	if (!parseTotpArgs(argc - 1, argv + 1, &opts)) {
		freeTotpOpts(&opts);
		return (1);
	}

	if (opts.passin) {
		passinPass = getPassword(opts.passin, env);
		if (!passinPass) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to get input password\n");
			freeTotpOpts(&opts);
			return (1);
		}
	}

	if (opts.passout) {
		passoutPass = getPassword(opts.passout, env);
		if (!passoutPass) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to get output password\n");
			free(passinPass);
			freeTotpOpts(&opts);
			return (1);
		}
	}

	t_totpEntry *entries = NULL;
	size_t entryCount = 0;
	if (!buildEntries(&opts, passinPass, &entries, &entryCount)) {
		ft_dprintf(STDERR_FILENO, "ft_ssl: totp: no valid TOTP entries found\n");
		free(passinPass);
		free(passoutPass);
		freeTotpOpts(&opts);
		return (1);
	}

	/* If a cipher is specified but no output password, prompt interactively */
	if (opts.cipher != NULL && passoutPass == NULL) {
		if (!opts.batch) {
			char *prompt = ft_strdup("Enter output password: ");
			passoutPass = promptPassword(prompt, 1);
			free(prompt);
			if (!passoutPass) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: no password provided for encryption\n");
				ret = 1;
				goto cleanup;
			}
		} else {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cipher specified but no output password in batch mode\n");
			ret = 1;
			goto cleanup;
		}
	}
	if (opts.outputFile || opts.cipher) {
		t_totpStore store;
		store.entries = entries;
		store.count = entryCount;
		char *pem = totpStoreToPem(&store, passoutPass, opts.cipher);
		if (pem) {
			int fd = opts.outputFile ? open(opts.outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0644) : STDOUT_FILENO;
			if (fd >= 0) {
				write(fd, pem, ft_strlen(pem));
				close(fd);
			}
			free(pem);
		} else {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: failed to encode store\n");
			ret = 1;
		}
		goto cleanup;
	}

	if (opts.generateUris) {
		char uriBuf[512];
		int outFd = STDOUT_FILENO;
		if (opts.outputFile) {
			outFd = open(opts.outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (outFd < 0) {
				ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cannot open '%s'\n", opts.outputFile);
				ret = 1;
				goto cleanup;
			}
		}
		for (size_t i = 0; i < entryCount; i++) {
			t_totpEntry *e = &entries[i];
			char secretB32[128];
			if (base32Encode(e->secret, e->secretLen, secretB32, sizeof(secretB32)) == (size_t)-1)
				continue;
			if (totpCreateUri(e->label, secretB32, e->issuer, e, uriBuf, sizeof(uriBuf)) == 0) {
				ft_dprintf(outFd, "%s\n", uriBuf);
				if (opts.showSecret)
					ft_dprintf(outFd, "Secret: %s\n", secretB32);
			}
		}
		if (outFd != STDOUT_FILENO)
			close(outFd);
		goto cleanup;
	}

	if (opts.live) {
		runLiveMode(entries, entryCount);
		goto cleanup;
	}

	uint64_t now = (uint64_t)time(NULL);
	int outFd = STDOUT_FILENO;
	if (opts.outputFile) {
		outFd = open(opts.outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (outFd < 0) {
			ft_dprintf(STDERR_FILENO, "ft_ssl: totp: cannot open '%s'\n", opts.outputFile);
			ret = 1;
			goto cleanup;
		}
	}
	char code[16];
	for (size_t i = 0; i < entryCount; i++) {
		if (totpGenerate(&entries[i], now, code) == 0) {
			ft_dprintf(outFd, "%s: %s\n",
					entries[i].label ? entries[i].label : "unknown",
					code);
		}
	}
	if (outFd != STDOUT_FILENO)
		close(outFd);

cleanup:
	for (size_t i = 0; i < entryCount; i++) {
		free(entries[i].label);
		free(entries[i].issuer);
	}
	free(entries);
	free(passinPass);
	free(passoutPass);
	freeTotpOpts(&opts);
	return (ret);
}
