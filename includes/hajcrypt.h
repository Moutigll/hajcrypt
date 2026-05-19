#ifndef HAJCRYPT_H
#define HAJCRYPT_H

#define HAJCRYPT_DPRINT(string, ...) ft_dprintf(STDERR_FILENO, string, ##__VA_ARGS__)
#define HAJCRYPT_SMALL_FOOTPRINT 0


#define P_RESET "\033[0m"

#define P_GREEN "\033[32m"
#define P_RED "\033[31m"

#endif /* HAJCRYPT_H */
