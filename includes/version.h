#ifndef HAJCRYPT_VERSION_H
#define HAJCRYPT_VERSION_H

#define HAJCRYPT_VERSION_MAJOR	0
#define HAJCRYPT_VERSION_MINOR	14
#define HAJCRYPT_VERSION_PATCH	1
#define HAJCRYPT_VERSION_STRING	"0.14.1"

#define HAJCRYPT_GIT_COMMIT_HASH	"022e22d"
#define HAJCRYPT_GIT_COMMIT_SUBJECT	"feat(cli): Add --nopad option to disable padding for block ciphers"
#define HAJCRYPT_GIT_COMMIT_DATE	"14 Jun 2026"

const char	*hajcryptVersion(void);
void		hajcryptVersionComponents(int *major, int *minor, int *patch);
int			hajcryptVersionCompare(const char *v1, const char *v2);

#endif /* HAJCRYPT_VERSION_H */
