/*
 * Perform a QUIC server-side handshake.
 *
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * libquic is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "netinet/quic.h"

/**
 * quic_server_session_init - setup for a QUIC handshake with Certificate on server side
 * @s: IPPROTO_QUIC type socket
 * @cred: gnutls certificate credentials
 * @alpns: ALPNs supported and split by ','
 *
 * Return values:
 * - On success, a gnutls_session_t session
 * - On error, NULL
 */
gnutls_session_t quic_server_session_init(int s, gnutls_certificate_credentials_t cred,
					  const char *alpns)
{
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
	int ret;

	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	ret = gnutls_priority_set_direct(session, QUIC_PRIORITY, NULL);
	if (ret)
		goto err_session;
	if (alpns) {
		ret = quic_session_set_alpn(session, alpns, strlen(alpns));
		if (ret)
			goto err_session;
	}

	gnutls_transport_set_int(session, s);

	return session;

/* XXX
	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
	}
*/

err_session:
	gnutls_deinit(session);
err:
	return NULL;
}

/**
 * quic_server_init - setup for a QUIC handshake with Certificate on server side
 * @pkey: PEM formatted private key
 * @pkey_len: length of the PEM formatted private key
 * @cert: PEM formatted certificate
 * @cert_len: length of the PEM formatted certificate
 *
 * Return values:
 * - On success, gnutls certificate credentials
 * - On error, NULL
 */
gnutls_certificate_credentials_t quic_server_init(const char *pkey, size_t pkey_len,
						  const char *cert, size_t cert_len)
{
	gnutls_certificate_credentials_t cred;
	gnutls_datum_t gcert, gkey;
	int ret;

	gcert.data = cert;
	gcert.size = cert_len;
	gkey.data = pkey;
	gkey.size = pkey_len;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = gnutls_certificate_set_x509_key_mem2(cred, &gcert, &gkey, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret)
		goto err_cred;

	return cred;

err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return NULL;
}
