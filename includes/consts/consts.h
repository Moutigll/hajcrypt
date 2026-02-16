#ifndef HAJCRYPT_CONSTS_H
#define HAJCRYPT_CONSTS_H

/* Header generator function type */
typedef int (*headerGenerator)(int fd);

/**
 * @brief Struct to represent a header file to generate, with its name and generator function.
 * The 'name' field is the base name of the header (e.g. "md5"),
 * and the 'generate' field is a function pointer to the function that generates the header content
 */
typedef struct s_header {
	const char		*name;
	headerGenerator	generate;
} t_header;

/**
 * @brief Generate the MD5 header file with initial state constants and sine-based constants.
 * @param fd - file descriptor to write the generated header content to
 * @return 0 on success, 1 on failure (e.g. write error)
 */
int generateMd5Header(int fd);

#endif /* HAJCRYPT_CONSTS_H */
