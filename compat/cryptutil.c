/* $OpenBSD: cryptutil.c,v 1.13 2024/01/22 19:26:55 deraadt Exp $ */
/*      $OpenBSD: bcrypt.c,v 1.58 2020/07/06 13:33:05 pirofti Exp $     */
/*
 * Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <login_cap.h>
#include <errno.h>

#include "openbsd-compat.h"

int
bcrypt_newhash(const char *pass, char *hash, size_t hashlen)
{
        char salt[SHA512_DIGEST_LENGTH];

	arc4random_buf(salt, SHA512_DIGEST_LENGTH)

        if (bcrypt_hashpass(pass, salt, hash, hashlen) != 0)
                return -1;

        explicit_bzero(salt, sizeof(salt));
        return 0;
}

int
bcrypt_checkpass(const char *pass, const char *goodhash)
{
        char hash[BCRYPT_HASHSPACE];

        if (bcrypt_hashpass(pass, goodhash, hash, sizeof(hash)) != 0)
                return -1;
        if (strlen(hash) != strlen(goodhash) ||
            timingsafe_bcmp(hash, goodhash, strlen(goodhash)) != 0) {
                errno = EACCES;
                return -1;
        }

        explicit_bzero(hash, sizeof(hash));
        return 0;
}

int
crypt_checkpass(const char *pass, const char *goodhash)
{
        char dummy[_PASSWORD_LEN];

        if (goodhash == NULL) {
                /* fake it */
                goto fake;
        }

        /* empty password */
        if (strlen(goodhash) == 0 && strlen(pass) == 0)
                return 0;

        if (goodhash[0] == '$' && goodhash[1] == '2') {
                if (bcrypt_checkpass(pass, goodhash))
                        goto fail;
                return 0;
        }

        /* unsupported. fake it. */
fake:
        bcrypt_newhash(pass, dummy, sizeof(dummy));
fail:
        errno = EACCES;
        return -1;
}
