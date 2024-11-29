// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <gnutls/abstract.h>
#include <sys/socket.h>
#include <linux/quic.h>

/* Socket option layer for QUIC */
#ifndef SOL_QUIC
#define SOL_QUIC		288
#endif

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC		261
#endif

#define QUIC_PRIORITY \
	"NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:" \
	"+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:" \
	"+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
	"%DISABLE_TLS13_COMPAT_MODE"

gnutls_session_t quic_server_session_init(int sockfd, gnutls_certificate_credentials_t cred,
					  const char *alpns);
gnutls_certificate_credentials_t quic_server_init(const char *pkey, size_t pkey_len,
						  const char *cert, size_t cert_len);

int quic_handshake(gnutls_session_t session);

int quic_session_get_data(gnutls_session_t session,
			  void *data, size_t *size);
int quic_session_set_data(gnutls_session_t session,
			  const void *data, size_t size);

int quic_session_get_alpn(gnutls_session_t session,
			  void *data, size_t *size);
int quic_session_set_alpn(gnutls_session_t session,
			  const void *data, size_t size);

ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len,
		     int64_t sid, uint32_t flags);
ssize_t quic_recvmsg(int sockfd, void *msg, size_t len,
		     int64_t *sid, uint32_t *flags);

void quic_set_log_func(void (*func)(int level, const char *msg));
void quic_set_log_level(int level);
