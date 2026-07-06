#include "../includes/version.h"
#include <stdio.h>

const char* hajcryptVersion(void)
{
    return (HAJCRYPT_VERSION_STRING);
}

void hajcryptVersionComponents(int *major, int *minor, int *patch)
{
    if (major) *major = HAJCRYPT_VERSION_MAJOR;
    if (minor) *minor = HAJCRYPT_VERSION_MINOR;
    if (patch) *patch = HAJCRYPT_VERSION_PATCH;
}

int hajcryptVersionCompare(const char *v1, const char *v2)
{
    int m1, n1, p1, m2, n2, p2;
    if (sscanf(v1, "%d.%d.%d", &m1, &n1, &p1) != 3) return -1;
    if (sscanf(v2, "%d.%d.%d", &m2, &n2, &p2) != 3) return 1;
    if (m1 != m2) return m1 - m2;
    if (n1 != n2) return n1 - n2;
    return (p1 - p2);
}
