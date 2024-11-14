/* OPENBSD ORIGINAL: lib/libc/crypt/cryptutil.c */
/* from https://github.com/OpenSMTPD/OpenSMTPD/ */

#include <errno.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#include <string.h>
#include <unistd.h>

#include "openbsd-compat.h"

int
crypt_checkpass(const char *pass, const char *goodhash)
{
	char *c;

	if (goodhash == NULL)
		goto fail;

	/* empty password */
	if (strlen(goodhash) == 0 && strlen(pass) == 0)
		return 0;

	c = crypt(pass, goodhash);
	if (c == NULL)
		goto fail;

	if (strcmp(c, goodhash) == 0)
		return 0;

fail:
	errno = EACCES;
	return -1;
}

