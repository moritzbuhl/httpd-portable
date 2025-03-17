/*	$$	*/

/*
 * Copyright (c) 2024 Moritz Buhl <mbuhl@openbsd.org>
 * Copyright (c) 2020 Matthias Pressfreund <mpfr@fn.de>
 * Copyright (c) 2006 - 2018 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/quic.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fnmatch.h>
#include <stdio.h>
#include <time.h>
#include <resolv.h>
#include <event.h>
#include <ctype.h>
#include <vis.h>
#include <fcntl.h>

#include "openbsd-compat.h"

#include "httpd.h"
#include "http.h"
#include "patterns.h"

void		 server_http3conn_free(struct client *);
void		 server_abort_http3(struct client *, unsigned int,
		    const char *);
void		 server_close_http3(struct client *);
int		 server_response3(struct httpd *, struct client *);
int		 server_http_authenticate(struct server_config *,
		    struct client *);
void		 server_read_http3range(struct bufferevent *, void *);
int		 server_writeheader_http3(struct client *, struct kv *,
		    void *);
char		*server_expand_http(struct client *, const char *,
		    char *, size_t);

static int
h3_dyn_nva_init(struct h3_dyn_nva *dnva)
{
	dnva->nvlen = 0;
	dnva->nvsize = 10;
	if ((dnva->nva = calloc(dnva->nvsize, sizeof(struct nghttp3_nv)))
	    == NULL)
		return (-1);
	return (0);
}

static void
h3_dyn_nva_reset(struct h3_dyn_nva *dnva)
{
	struct nghttp3_nv *nv;
	int i;

	for (i = 0; i < dnva->nvlen; i++) {
		nv = &(dnva->nva[i]);
		free(nv->name);
		free(nv->value);
	}
	memset(dnva->nva, 0, dnva->nvlen * sizeof(struct nghttp3_nv));
	dnva->nvlen = 0;
}

static void
h3_dyn_nva_free(struct h3_dyn_nva *dnva)
{
	struct nghttp3_nv *nv;
	int i;

	for (i = 0; i < dnva->nvlen; i++) {
		nv = &(dnva->nva[i]);
		free(nv->name);
		free(nv->value);
	}

	free(dnva->nva);
}

static int
h3_dyn_nva_add(struct h3_dyn_nva *dnva, const char *key, char *value)
{
	struct nghttp3_nv *nv = &(dnva->nva[dnva->nvlen]);

	if ((nv->name = (uint8_t *)strdup(key)) == NULL)
		return (-1);
	nv->namelen = strlen(key);
	if (value) {
		if ((nv->value = (uint8_t *)strdup(value)) == NULL) {
			free(nv->name);
			nv->namelen = 0;
			return (-1);
		}
		nv->valuelen = strlen(value);
	}

	dnva->nvlen++;
	if (dnva->nvlen == dnva->nvsize) {
		if ((dnva->nva = recallocarray(dnva->nva, dnva->nvsize,
		    dnva->nvsize * 2, sizeof(struct nghttp3_nv))) == NULL)
			return (-1);
		dnva->nvsize *= 2;
	}
	return (0);
}

static nghttp3_ssize
h3_read_data(nghttp3_conn *conn, int64_t sid, nghttp3_vec *vecs, size_t nvs,
    uint32_t *pflags, void *arg, void *sarg)
{
	struct h3_stream_evbuf	*sb = sarg;
	size_t			 len, written = 0;
	int			 n, i;

	len = EVBUFFER_LENGTH(sb->eb);
	if (len == 0) {
		if (sb->eof) {
			*pflags |= NGHTTP3_DATA_FLAG_EOF;
			return 0;
		}
		return NGHTTP3_ERR_WOULDBLOCK;
	}
	evbuffer_ptr_set(sb->eb, &sb->ep, sb->ep.pos, EVBUFFER_PTR_SET);
	n = evbuffer_peek(sb->eb, -1, &sb->ep,
	    (struct evbuffer_iovec *)vecs, nvs);
	if (n == 0)
		return NGHTTP3_ERR_WOULDBLOCK;
	for (i = 0; i < n; i++)
		written += vecs[i].len;
	evbuffer_ptr_set(sb->eb, &sb->ep, written, EVBUFFER_PTR_ADD);
	if (sb->eof && written == len)
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
	return n;
}

static int
h3_acked_stream_data(nghttp3_conn *conn, int64_t sid, uint64_t len, void *arg,
    void *sarg)
{
	struct h3_stream_evbuf	*sb = sarg;

	evbuffer_drain(sb->eb, len);
	if (sb->ep.pos > 0) {
		if (len > sb->ep.pos)
			sb->ep.pos = 0;
		else
			sb->ep.pos -= len;
	}
	if (sb->eof) {
		if (EVBUFFER_LENGTH(sb->eb) == 0) {
			evbuffer_free(sb->eb);
			free(sb);
			return (0);
		}
	}
	return (0);
}

static int
h3_stream_close(nghttp3_conn *conn, int64_t sid, uint64_t error, void *arg,
    void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_deferred_consume(nghttp3_conn *conn, int64_t sid, size_t n, void *arg,
    void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_begin_headers(nghttp3_conn *conn, int64_t sid, void *arg, void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_recv_header(nghttp3_conn *conn, int64_t sid, int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *arg,
    void *sarg)
{
	struct client		*clt = arg;
	struct http_descriptor	*desc = clt->clt_descreq;
	char			*key = NULL;
	char			*val = NULL;
	nghttp3_vec		 k = nghttp3_rcbuf_get_buf(name);
	nghttp3_vec		 v = nghttp3_rcbuf_get_buf(value);


	if (asprintf(&val, "%.*s", (int)v.len, v.base) == -1) {
		log_warn("asprintf");
		return (-1);
	}
	
	switch (token) {
	case NGHTTP3_QPACK_TOKEN__METHOD:
		desc->http_method = server_httpmethod_byname(val);
		free(val);
		if (desc->http_method == HTTP_METHOD_NONE) {
			server_abort_http3(clt, 400, "malformed");
			return (-1);
		}
		break;
	case NGHTTP3_QPACK_TOKEN__PATH:
		desc->http_path = val;
		break;
	case NGHTTP3_QPACK_TOKEN_CONTENT_LENGTH:
		if (desc->http_method == HTTP_METHOD_TRACE ||
		    desc->http_method == HTTP_METHOD_CONNECT)
			server_abort_http3(clt, 400, "malformed");
		/* FALLTHROUGH */
	default:
		if (asprintf(&key, "%.*s", (int)k.len, k.base) == -1) {
			log_warn("asprintf");
			return (-1);
		}

		if (kv_add(&desc->http_headers, key, val) == NULL)
			return (-1);
	}

	return (0);
}

static int
h3_end_headers(nghttp3_conn *conn, int64_t sid, int fin, void *arg, void *sarg)
{
	struct client		*clt = arg;
	struct http_descriptor  *desc = clt->clt_descreq;

	DPRINTF("%s", __func__);
	if (desc->http_method == HTTP_METHOD_NONE)
		return (-1);
	if (desc->http_path == NULL)
		return (-1);
	if ((desc->http_version = strdup("HTTP/3")) == NULL)
		return (-1);

	server_response_http3(clt);
	return (0);
}

static int
h3_begin_trailers(nghttp3_conn *conn, int64_t sid, void *arg, void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_recv_trailer(nghttp3_conn *conn, int64_t sid, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *arg, void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_end_trailers(nghttp3_conn *conn, int64_t sid, int fin, void *arg, void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_stop_sending(nghttp3_conn *conn, int64_t sid, uint64_t app_error_code,
    void *arg, void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_reset_stream(nghttp3_conn *conn, int64_t sid, uint64_t error, void *arg,
    void *sarg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings,
    void *arg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_shutdown(nghttp3_conn *conn, int64_t id, void *arg)
{
	DPRINTF("%s", __func__);
	return (0);
}

static int
h3_recv_data(nghttp3_conn *conn, int64_t sid, const uint8_t *data, size_t len,
    void *arg, void *sarg)
{
	DPRINTF("%s: len=%lu", __func__, len);
	DPRINTF("%.s", len, data);
	return (0);
}

static int
h3_end_stream(nghttp3_conn *conn, int64_t sid, void *arg, void *sarg)
{
	struct client			*clt = arg;
	struct http_descriptor		*resp = clt->clt_descresp;
	struct evbuffer			*eb;
	struct nghttp3_data_reader	 dr;

	DPRINTF("%s", __func__);

	if ((clt->clt_h3seb = malloc(sizeof(struct h3_stream_evbuf))) == NULL) {
		server_close(clt, "failed to allocate stream event buffer");
		return (-1);
	}
	if ((eb = evbuffer_new()) == NULL) {
		server_close(clt, "failed to allocate stream buffer");
		return (-1);
	}
	evbuffer_setcb(eb, server_response_http3_stream, clt->clt_h3seb);
	nghttp3_conn_set_stream_user_data(conn, sid, clt->clt_h3seb);
	clt->clt_h3seb->clt = clt;
	clt->clt_h3seb->eb = eb;
	clt->clt_h3seb->sid = sid;
	clt->clt_h3seb->eof = 0;
	evbuffer_ptr_set(eb, &clt->clt_h3seb->ep, 0, EVBUFFER_PTR_SET);

	kv_purge(&clt->clt_descresp->http_headers);
	h3_dyn_nva_reset(&clt->clt_h3dnva);
	if (server_response3(httpd_env, clt) == -1)
		return (0); /* called server_abort_http3 */

	dr.read_data = h3_read_data;
	return nghttp3_conn_submit_response(conn, sid, clt->clt_h3dnva.nva,
	    clt->clt_h3dnva.nvlen, &dr);
}

void
server_http3(void)
{
	/* nothing */
}

static int64_t
stream_open(int s, uint32_t flags) {
	struct quic_stream_info si;
	socklen_t len = sizeof(si);

	si.stream_id = -1;
	si.stream_flags = flags;
	if(getsockopt(s, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &si, &len))
		return (-1);
	return si.stream_id;
}

int
server_http3conn_init(struct client *clt)
{
	int64_t ctrl, enc, dec;
	struct quic_transport_param param;
	nghttp3_callbacks callbacks = {
		h3_acked_stream_data,
		h3_stream_close,
		h3_recv_data,
		h3_deferred_consume,
		h3_begin_headers,
		h3_recv_header,
		h3_end_headers,
		h3_begin_trailers,
		h3_recv_trailer,
		h3_end_trailers,
		h3_stop_sending,
		h3_end_stream,
		h3_reset_stream,
		h3_shutdown,
		h3_recv_settings,
	};
	nghttp3_settings settings;
	unsigned int plen;

	memset(&param, 0, sizeof(param));
	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	if (nghttp3_conn_server_new(&clt->clt_h3conn, &callbacks, &settings,
	    NULL, clt))
		return (-1);

	if (h3_dyn_nva_init(&clt->clt_h3dnva) == -1)
		return (-1);

	plen = sizeof(param);
	if (getsockopt(clt->clt_s, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
	    &param, &plen) == -1) {
		log_warn("socket getsockopt remote transport param");
		return (-1);
	}
	nghttp3_conn_set_max_client_streams_bidi(clt->clt_h3conn,
	    param.max_streams_bidi);

	
	if ((ctrl = stream_open(clt->clt_s, MSG_STREAM_UNI)) == -1) {
		log_warn("stream_open ctrl");
		return (-1);
	}
	if (nghttp3_conn_bind_control_stream(clt->clt_h3conn, ctrl)) {
		log_warnx("nghttp3_conn_bind_control_stream");
		return (-1);
	}

	if ((enc = stream_open(clt->clt_s, MSG_STREAM_UNI)) == -1) {
		log_warn("stream_open enc");
		return (-1);
	}
	if ((dec = stream_open(clt->clt_s, MSG_STREAM_UNI)) == -1) {
		log_warn("stream_open dec");
		return (-1);
	}
	if (nghttp3_conn_bind_qpack_streams(clt->clt_h3conn, enc, dec)) {
		log_warnx("nghttp3_conn_bind_qpack_streams");
		return (-1);
	}

	DPRINTF("%s ctrl=%llu enc=%llu dec=%llu", __func__, ctrl, enc, dec);

	return (0);
}

void
server_http3conn_free(struct client *clt)
{
	if (clt->clt_h3conn)
		nghttp3_conn_del(clt->clt_h3conn);
	if (clt->clt_h3dnva.nvlen)
		h3_dyn_nva_free(&clt->clt_h3dnva);
}

ssize_t
server_http3_recv(struct client *clt, char *buf, size_t len, int64_t *sid,
    uint32_t *flags)
{
	struct msghdr msg;
	struct cmsghdr *cm = NULL;
	struct iovec iov;
	ssize_t n;
	struct quic_stream_info info;
	char cmsgbuf[CMSG_SPACE(sizeof(info))];

	memset(&msg, 0, sizeof(msg));

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	n = recvmsg(clt->clt_s, &msg, *flags);
	if (n == -1)
		return n;

	*flags = msg.msg_flags;

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm))
		if (cm->cmsg_level == SOL_QUIC &&
		    cm->cmsg_type == QUIC_STREAM_INFO)
			break;
	if (cm && cm->cmsg_len == CMSG_LEN(sizeof(info))) {
		memcpy(&info, CMSG_DATA(cm), sizeof(info));
		*sid = info.stream_id;
		*flags |= info.stream_flags;
	}
	return n;
}

ssize_t
server_http3_send(struct client *clt, struct iovec *iov, unsigned int nvs,
    int64_t sid, int fin)
{
	struct msghdr msg;
	struct cmsghdr *cm;
	struct quic_stream_info *info;
	char cmsgbuf[CMSG_SPACE(sizeof(*info))];

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = nvs;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_QUIC;
	cm->cmsg_type = 0;
	cm->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_stream_info *)CMSG_DATA(cm);
	info->stream_id = sid;
	info->stream_flags = fin ? MSG_STREAM_FIN : 0;

	return sendmsg(clt->clt_s, &msg, 0);
}

void
server_http3_quic_event(struct client *clt, char *buf, size_t len, int64_t sid)
{
	union quic_event qev;

	if(len < 1)
		server_close(clt, "empty quic event");

	switch(buf[0]) {
	case QUIC_EVENT_STREAM_UPDATE:
		struct quic_stream_update qsu;
		if(len < 1 + sizeof(qsu))
			server_close(clt, "malformed stream update event");
		memcpy(&qsu, &buf[1], sizeof(qsu));
		DPRINTF("%s: stream update id=%llu state=%u errcode=%u "
		    "finalsz=%llu", __func__, qsu.id, qsu.state, qsu.errcode,
		    qsu.finalsz);
		break;
	case QUIC_EVENT_STREAM_MAX_DATA:
		struct quic_stream_max_data qsmd;
		if(len < 1 + sizeof(qsmd))
			server_close(clt, "malformed stream max data event");
		memcpy(&qsmd, &buf[1], sizeof(qsmd));
		DPRINTF("%s: stream max data id=%llu max_data=%llu", __func__,
		    qsmd.id, qsmd.max_data);
		if (nghttp3_conn_unblock_stream(clt->clt_h3conn, qsmd.id)) {
			log_warnx("nghttp3_conn_unblock_stream");
			server_close(clt, "cannot unblock stream");
		}
		break;
	case QUIC_EVENT_CONNECTION_CLOSE:
		struct quic_connection_close qcc;
		char *phrase = &buf[1 + sizeof(qcc)];
		if(len < 1 + sizeof(qcc))
			server_close(clt, "malformed connection close event");
		memcpy(&qcc, &buf[1], sizeof(qcc));
		DPRINTF("%s: connection close errcode=%u frame=%hhu phrase=%s",
		    __func__, qcc.errcode, qcc.frame, phrase);
		clt->clt_done = 1;
		break;
	default:
		server_close(clt, "unknown quic event");
	}
}

void
server_read3(struct bufferevent *bev, void *arg)
{
	struct h3_stream_evbuf	*sb = arg;
	struct client		*clt = sb->clt;
	struct h3_stream_evbuf	*tmp = clt->clt_h3seb;
	struct evbuffer		*src = EVBUFFER_INPUT(bev);

	getmonotime(&clt->clt_tv_last);

	if (!EVBUFFER_LENGTH(src))
		return;
	clt->clt_h3seb = sb;
	if (server_bufferevent_write_buffer(clt, src) == -1)
		goto fail;
	clt->clt_h3seb = tmp;
	if (clt->clt_done)
		goto done;

	return;
 done:
	(*bev->errorcb)(bev, EVBUFFER_READ, bev->cbarg);
	return;
 fail:
	clt->clt_h3seb = tmp;
	server_close(clt, strerror(errno));
}

void
server_write3(struct bufferevent *bev, void *arg)
{
	struct h3_stream_evbuf	*sb = arg;
	struct client	  	*clt = sb->clt;
	struct evbuffer		*dst = EVBUFFER_OUTPUT(bev);

	if (EVBUFFER_LENGTH(dst) == 0 &&
	    clt->clt_toread == TOREAD_HTTP_NONE)
		goto done;

	getmonotime(&clt->clt_tv_last);

	if (clt->clt_done)
		goto done;

	return;
 done:
	(*bev->errorcb)(bev, EVBUFFER_WRITE, bev->cbarg);
	return;
}

void
server_read_http3(int fd, void *arg)
{
	struct client		*clt = arg;
	int64_t			 sid = -1;
	uint32_t		 flags = 0;
	int			 n, fin;
	char			 buf[65536];

	getmonotime(&clt->clt_tv_last);

	if ((n = server_http3_recv(clt, &buf, sizeof(buf), &sid, &flags)) ==
	    -1) {
		log_warnx("server_http3_recv");
		goto fail;
	}
	if (flags & MSG_NOTIFICATION) {
		server_http3_quic_event(clt, buf, n, sid);
		goto done;
	}
	fin = flags & MSG_STREAM_FIN;
	if (nghttp3_conn_read_stream(clt->clt_h3conn, sid, buf, n, fin) < 0) {
		log_warnx("nghttp3_conn_read_stream");
		goto fail;
	}

 done:
	if (clt->clt_done) {
		server_close(clt, "done");
		return;
	}
	return;
 fail:
	server_abort_http3(clt, 500, strerror(errno));
	server_close(clt, "read error");
	return;
}

void
server_abort_http3(struct client *clt, unsigned int code, const char *msg)
{
	struct server_config		*srv_conf = clt->clt_srv_conf;
	struct http_descriptor		*resp = clt->clt_descresp;
	const char			*httperr = NULL, *style;
	char				*httpmsg, *body = NULL;
	char				 tmbuf[32], hbuf[128];
	char				 buf[IBUF_READ_SIZE];
	char				*escapedmsg = NULL;
	char				 cstr[5];
	ssize_t				 bodylen = 0;
	struct kv			*cl;
	struct nghttp3_data_reader	 dr;

	DPRINTF("%s code=%u msg=%s", __func__, code, msg);

	if (code == 0) {
		server_close(clt, "dropped");
		return;
	}

	if ((httperr = server_httperror_byid(code)) == NULL)
		httperr = "Unknown Error";

	if (server_log_http(clt, code, 0) == -1)
		goto done;

	/* Some system information */
	if (print_host(&srv_conf->ss, hbuf, sizeof(hbuf)) == NULL)
		goto done;

	if (server_http_time(time(NULL), tmbuf, sizeof(tmbuf)) <= 0)
		goto done;

	/* Do not send details of the Internal Server Error */
	switch (code) {
	case 301:
	case 302:
	case 303:
	case 307:
	case 308:
		if (msg == NULL)
			break;
		memset(buf, 0, sizeof(buf));
		if (server_expand_http(clt, msg, buf, sizeof(buf)) == NULL)
			goto done;
		if (kv_add(&resp->http_headers, "Location", buf) == NULL)
			code = 500;
		msg = buf;
		break;
	case 401:
		if (msg == NULL)
			break;
		if (stravis(&escapedmsg, msg, VIS_DQ) == -1) {
			code = 500;
		} else if ((cl = kv_add(&resp->http_headers, "WWW-Authenticate",
		    NULL)) == NULL ||
		    kv_set(cl, "Basic realm=\"%s\"", escapedmsg) == -1) {
			code = 500;
		}
		break;
	case 416:
		if (msg == NULL)
			break;
		if (kv_add(&resp->http_headers, "Content-Range", msg) == NULL)
			code = 500;
		break;
	default:
		/*
		 * Do not send details of the error.  Traditionally,
		 * web servers responsed with the request path on 40x
		 * errors which could be abused to inject JavaScript etc.
		 * Instead of sanitizing the path here, we just don't
		 * reprint it.
		 */
		break;
	}

	free(escapedmsg);

	if ((code >= 100 && code < 200) || code == 204)
		goto send;
	if ((srv_conf->flags & SRVFLAG_ERRDOCS) == 0)
		goto builtin; /* errdocs not enabled */
	if ((size_t)snprintf(cstr, sizeof(cstr), "%03u", code) >= sizeof(cstr))
		goto builtin;

	if ((body = read_errdoc(srv_conf->errdocroot, cstr)) == NULL &&
	    (body = read_errdoc(srv_conf->errdocroot, HTTPD_ERRDOCTEMPLATE))
	    == NULL)
		goto builtin;

	body = replace_var(body, "$HTTP_ERROR", httperr);
	body = replace_var(body, "$RESPONSE_CODE", cstr);
	body = replace_var(body, "$SERVER_SOFTWARE", HTTPD_SERVERNAME);
	bodylen = strlen(body);
	goto send;

 builtin:
	/* A CSS stylesheet allows minimal customization by the user */
	style = "body { background-color: white; color: black; font-family: "
	    "'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif; }\n"
	    "hr { border: 0; border-bottom: 1px dashed; }\n"
	    "@media (prefers-color-scheme: dark) {\n"
	    "body { background-color: #1E1F21; color: #EEEFF1; }\n"
	    "a { color: #BAD7FF; }\n}";

	/* Generate simple HTML error document */
	if ((bodylen = asprintf(&body,
	    "<!DOCTYPE html>\n"
	    "<html>\n"
	    "<head>\n"
	    "<meta charset=\"utf-8\">\n"
	    "<title>%03d %s</title>\n"
	    "<style type=\"text/css\"><!--\n%s\n--></style>\n"
	    "</head>\n"
	    "<body>\n"
	    "<h1>%03d %s</h1>\n"
	    "<hr>\n<address>%s</address>\n"
	    "</body>\n"
	    "</html>\n",
	    code, httperr, style, code, httperr, HTTPD_SERVERNAME)) == -1) {
		body = NULL;
		goto done;
	}

 send:
	if ((cl = kv_add(&resp->http_headers, ":status", NULL)) == NULL ||
	    kv_set(cl, "%03d", code) == -1)
		goto done;
	if (kv_add(&resp->http_headers, "Date", tmbuf) == NULL)
		goto done;
	if (kv_add(&resp->http_headers, "Server", HTTPD_SERVERNAME) == NULL)
		goto done;
	if (kv_add(&resp->http_headers, "Content-Type", "text/html") == NULL)
		goto done;

	/* HSTS header */
	if (srv_conf->flags & SRVFLAG_SERVER_HSTS &&
	    srv_conf->flags & SRVFLAG_TLS) {
		if ((cl =
		    kv_add(&resp->http_headers, "Strict-Transport-Security",
		    NULL)) == NULL ||
		    kv_set(cl, "max-age=%d%s%s", srv_conf->hsts_max_age,
		    srv_conf->hsts_flags & HSTSFLAG_SUBDOMAINS ?
		    "; includeSubDomains" : "",
		    srv_conf->hsts_flags & HSTSFLAG_PRELOAD ?
		    "; preload" : "") == -1)
			goto done;
	}

	if (bodylen) {
		if ((cl = kv_add(&resp->http_headers, "Content-Length", NULL))
		    == NULL || kv_set(cl, "%zd", bodylen) == -1)
			goto done;
	}

	if (server_headers(clt, resp, server_writeheader_http3, NULL) == -1)
		log_warnx("%s: server_headers", __func__);

	
	dr.read_data = h3_read_data;
	nghttp3_conn_submit_response(clt->clt_h3conn, clt->clt_h3seb->sid,
	    clt->clt_h3dnva.nva, clt->clt_h3dnva.nvlen, &dr);

	if (bodylen) {
		clt->clt_h3seb->eof = 1;
		server_bufferevent_write(clt, body, bodylen);
	}

 done:
	free(body);
}

void
server_close_http3(struct client *clt)
{
	server_http3conn_free(clt);
	clt->clt_h3conn = NULL;
}

int
server_response3(struct httpd *httpd, struct client *clt)
{
	char			 path[PATH_MAX];
	char			 hostname[HOST_NAME_MAX+1];
	struct http_descriptor	*desc = clt->clt_descreq;
	struct http_descriptor	*resp = clt->clt_descresp;
	struct server		*srv = clt->clt_srv;
	struct server_config	*srv_conf = &srv->srv_conf;
	struct kv		*kv, key, *host;
	struct str_find		 sm;
	int			 portval = -1, ret;
	char			*hostval, *query;
	const char		*errstr = NULL;

	/* Preserve original path */
	if (desc->http_path == NULL ||
	    (desc->http_path_orig = strdup(desc->http_path)) == NULL)
		goto fail;

	/* Decode the URL */
	if (url_decode(desc->http_path) == NULL)
		goto fail;

	/* Canonicalize the request path */
	if (canonicalize_path(desc->http_path, path, sizeof(path)) == NULL)
		goto fail;
	free(desc->http_path);
	if ((desc->http_path = strdup(path)) == NULL)
		goto fail;

	key.kv_key = ":authority";
	if ((host = kv_find(&desc->http_headers, &key)) != NULL &&
	    host->kv_value == NULL)
			goto fail;

	key.kv_key = "connection";
	if ((kv = kv_find(&desc->http_headers, &key)) != NULL &&
	    strcasecmp("keep-alive", kv->kv_value) == 0)
		clt->clt_persist++;
	else
		clt->clt_persist = 0;

	if (host != NULL) {
		if ((hostval = server_http_parsehost(host->kv_value,
		    hostname, sizeof(hostname), &portval)) == NULL)
			goto fail;

		TAILQ_FOREACH(srv_conf, &srv->srv_hosts, entry) {
#ifdef DEBUG
			if ((srv_conf->flags & SRVFLAG_LOCATION) == 0) {
				DPRINTF("%s: virtual host \"%s:%u\""
				    " host \"%s\" (\"%s\")",
				    __func__, srv_conf->name,
				    ntohs(srv_conf->port), host->kv_value,
				    hostname);
			}
#endif
			if (srv_conf->flags & SRVFLAG_LOCATION)
				continue;
			else if (srv_conf->flags & SRVFLAG_SERVER_MATCH) {
				str_find(hostname, srv_conf->name,
				    &sm, 1, &errstr);
				ret = errstr == NULL ? 0 : -1;
			} else {
				ret = fnmatch(srv_conf->name,
				    hostname, FNM_CASEFOLD);
			}
			if (ret == 0 &&
			    (portval == -1 || portval == srv_conf->port)) {
				/* Replace host configuration */
				clt->clt_srv_conf = srv_conf;
				srv_conf = NULL;
				break;
			}
		}
	}

	if (srv_conf != NULL) {
		/* Use the actual server IP address */
		if (server_http_host(&clt->clt_srv_ss, hostname,
		    sizeof(hostname)) == NULL)
			goto fail;
	} else {
		/* Host header was valid and found */
		if (strlcpy(hostname, host->kv_value, sizeof(hostname)) >=
		    sizeof(hostname))
			goto fail;
		srv_conf = clt->clt_srv_conf;
	}


	if (clt->clt_persist >= srv_conf->maxrequests)
		clt->clt_persist = 0;

	/* pipelining should end after the first "idempotent" method */
	if (clt->clt_pipelining && clt->clt_toread > 0)
		clt->clt_persist = 0;

	if ((desc->http_host = strdup(hostname)) == NULL)
		goto fail;

	/* Now fill in the mandatory parts of the response descriptor */
	resp->http_method = desc->http_method;
	if ((resp->http_version = strdup(desc->http_version)) == NULL)
		goto fail;

	/* Now search for the location */
	if ((srv_conf = server_getlocation(clt, desc->http_path)) == NULL) {
		server_abort_http3(clt, 500, desc->http_path);
		return (-1);
	}

	/* Optional rewrite */
	if (srv_conf->flags & SRVFLAG_PATH_REWRITE) {
		/* Expand macros */
		if (server_expand_http(clt, srv_conf->path,
		    path, sizeof(path)) == NULL)
			goto fail;

		/*
		 * Reset and update the query.  The updated query must already
		 * be URL encoded - either specified by the user or by using the
		 * original $QUERY_STRING.
		 */
		free(desc->http_query_alias);
		desc->http_query_alias = NULL;
		if ((query = strchr(path, '?')) != NULL) {
			*query++ = '\0';
			if ((desc->http_query_alias = strdup(query)) == NULL)
				goto fail;
		}

		/* Canonicalize the updated request path */
		if (canonicalize_path(path,
		    path, sizeof(path)) == NULL)
			goto fail;

		log_debug("%s: rewrote %s?%s -> %s?%s", __func__,

		    desc->http_path, desc->http_query ? desc->http_query : "",
		    path, query ? query : "");

		free(desc->http_path_alias);
		if ((desc->http_path_alias = strdup(path)) == NULL)
			goto fail;

		/* Now search for the updated location */
		if ((srv_conf = server_getlocation(clt,
		    desc->http_path_alias)) == NULL) {
			server_abort_http3(clt, 500, desc->http_path_alias);
			return (-1);
		}
	}

	if (clt->clt_toread > 0 && (size_t)clt->clt_toread >
	    srv_conf->maxrequestbody) {
		server_abort_http3(clt, 413, "request body too large");
		return (-1);
	}

	if (srv_conf->flags & SRVFLAG_BLOCK) {
		server_abort_http3(clt, srv_conf->return_code,
		    srv_conf->return_uri);
		return (-1);
	} else if (srv_conf->flags & SRVFLAG_AUTH &&
	    server_http_authenticate(srv_conf, clt) == -1) {
		server_abort_http3(clt, 401, srv_conf->auth_realm);
		return (-1);
	} else
		return (server_file(httpd, clt));
 fail:
	server_abort_http3(clt, 400, "bad request");
	return (-1);
}

int
server_writeheader_http3(struct client *clt, struct kv *hdr, void *arg)
{
	char		*ptr;
	const char	*key;

	/* The key might have been updated in the parent */
	if (hdr->kv_parent != NULL && hdr->kv_parent->kv_key != NULL)
		key = hdr->kv_parent->kv_key;
	else
		key = hdr->kv_key;

	ptr = hdr->kv_value;
	if (h3_dyn_nva_add(&clt->clt_h3dnva, key, ptr) == -1)
		return (-1);
	DPRINTF("%s: %s: %s", __func__, key,
	    hdr->kv_value == NULL ? "" : hdr->kv_value);

	return (0);
}

void 
server_response_http3_stream(struct evbuffer *buf, size_t old, size_t now,
    void *arg)
{
	struct h3_stream_evbuf	*sb = arg;
	struct client		*clt = sb->clt;

	if (old > now)
		return;

	nghttp3_conn_resume_stream(clt->clt_h3conn, sb->sid);
	server_response_http3(clt);
}

void 
server_response_http3(struct client *clt)
{
	struct iovec	iovs[256];
	int64_t		sid = -1;
	ssize_t		nvs;
	int		n, fin;

	while (1) {
		fin = 0;
		nvs = nghttp3_conn_writev_stream(clt->clt_h3conn, &sid, &fin,
		    (struct nghttp3_vec *)iovs, 256);
		if (nvs < 0) {
			log_warnx("nghttp3_conn_writev_stream: %lld", nvs);
			break;
		}
		if (sid == -1)
			break;
		if ((n = server_http3_send(clt, iovs, nvs, sid, fin)) == -1) {
			if (errno == ENOSPC) {
				nghttp3_conn_block_stream(clt->clt_h3conn, sid);
				break;
			}
			if (errno == EAGAIN)
				break;
			log_warn("server_http3_send");
			break;
		}
		if (nghttp3_conn_add_write_offset(clt->clt_h3conn, sid, n)) {
			log_warnx("nghttp3_conn_add_write_offset");
			break;
		}
		if (nghttp3_conn_add_ack_offset(clt->clt_h3conn, sid, n)) {
			log_warnx("nghttp3_conn_add_write_offset");
			break;
		}
		if (fin && --clt->clt_h3write == 0)
			event_again(&clt->clt_ev, clt->clt_s, EV_TIMEOUT |
			    EV_READ | EV_PERSIST, server_quic_ev_switch,
			    &clt->clt_tv_start, &clt->clt_timeout, clt);
	}
}
