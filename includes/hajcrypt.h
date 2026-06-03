#ifndef HAJCRYPT_H
#define HAJCRYPT_H

#define HAJCRYPT_DPRINT(string, ...) ft_dprintf(STDERR_FILENO, string, ##__VA_ARGS__)
#define HAJCRYPT_SMALL_FOOTPRINT 0


#define P_RESET "\033[0m"

#define P_GREEN "\033[32m"
#define P_RED "\033[31m"
#define P_ORANGE "\033[33m"

/* Macro for concatenating tokens */
#ifndef HC_CONCAT
# define HC_CONCAT_INNER(a, b) a ## b
# define HC_CONCAT(a, b) HC_CONCAT_INNER(a, b)
#endif

/* Macro for concatenating three tokens */
#ifndef HC_CONCAT3
# define HC_CONCAT3_INNER(a, b, c) a ## b ## c
# define HC_CONCAT3(a, b, c) HC_CONCAT3_INNER(a, b, c)
#endif

/* Macro for stringifying tokens */
#ifndef HC_STRINGIFY
# define HC_STRINGIFY_INNER(x) #x
# define HC_STRINGIFY(x) HC_STRINGIFY_INNER(x)
#endif


#endif /* HAJCRYPT_H */
