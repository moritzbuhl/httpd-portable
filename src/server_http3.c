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
#include <linux/quic.h>

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

void		 server_httpdesc_free(struct http_descriptor *); // XXX
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
	memset(dnva->nva, 0, dnva->nvlen * sizeof(struct nghttp3_nv));
	dnva->nvlen = 0;
}

static int
h3_dyn_nva_add(struct h3_dyn_nva *dnva, const char *key, char *value)
{
	struct nghttp3_nv *nv = &(dnva->nva[dnva->nvlen]);

	nv->name = (uint8_t *)key;
        nv->namelen = strlen(key);
	if (value) {
		nv->value = (uint8_t *)value;
		nv->valuelen = strlen(value);
	}
        /* XXX: make sure kvs are not deleted */
	/* nv->flags = NGHTTP3_NV_FLAG_NO_COPY_NAME |
	    NGHTTP3_NV_FLAG_NO_COPY_VALUE; */

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
h3_read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec, size_t veccnt, uint32_t *pflags, void *user_data, void *stream_user_data)
{
	/* XXX */
	return 0; // num vecs;
}

static int
h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id, uint64_t datalen, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t nconsumed, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *arg, void *sarg)
{
	struct client		*clt = arg;
	struct http_descriptor	*desc = clt->clt_descreq;
	char			*key = NULL;
	char			*val = NULL;
	struct kv		*hdr = NULL;
	nghttp3_vec		 k = nghttp3_rcbuf_get_buf(name);
	nghttp3_vec		 v = nghttp3_rcbuf_get_buf(value);

	log_debug("%s: sid=%lld %.*s: %.*s", __func__, stream_id, (int)k.len,
	    k.base, (int)v.len, v.base);

	/* XXX: don't do this for every header? */
	if (asprintf(&val, "%.*s", (int)v.len, v.base) == -1) {
		log_warn("asprintf");
		return (-1);
	}
	
	switch (token) {
	case NGHTTP3_QPACK_TOKEN__METHOD:
		if ((desc->http_method = server_httpmethod_byname(val))
		    == HTTP_METHOD_NONE) {
			/* XXX server_abort_http3(clt, 400, "malformed"); */
			return (-1);
		}
		free(val);
		break;
	case NGHTTP3_QPACK_TOKEN__PATH:
		desc->http_path = val;
		break;
	case NGHTTP3_QPACK_TOKEN_CONTENT_LENGTH:
		if (desc->http_method == HTTP_METHOD_TRACE ||
		    desc->http_method == HTTP_METHOD_CONNECT)
			server_abort_http(clt, 400, "malformed");
		/* FALLTHROUGH */
	default:
		if (asprintf(&key, "%.*s", (int)k.len, k.base) == -1) {
			log_warn("asprintf");
			return (-1);
		}

		if ((hdr = kv_add(&desc->http_headers, key, val)) == NULL)
			return (-1);
	}

	return (0);
}

static int
h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *arg, void *sarg)
{
	struct client		*clt = arg;
	struct http_descriptor  *desc = clt->clt_descreq;

	log_debug("%s", __func__);
	if (desc->http_method == HTTP_METHOD_NONE)
		return (-1);
	if (desc->http_path == NULL)
		return (-1);
	if ((desc->http_version = strdup("HTTP/3")) == NULL)
		return (-1);

	clt->clt_headersdone = 1;
	return (0);
}

static int
h3_begin_trailers(nghttp3_conn *conn, int64_t stream_id, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_recv_trailer(nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_end_trailers(nghttp3_conn *conn, int64_t stream_id, int fin, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_reset_stream(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *arg, void *sarg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings, void *arg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_shutdown(nghttp3_conn *conn, int64_t id, void *arg)
{
	log_debug("%s", __func__);
	return (0);
}

static int
h3_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen, void *arg, void *sarg)
{
	static size_t total;
	int i;

	for (i = 0; i < datalen; i++)
		log_info("%c", data[i]);

	total += datalen;
	log_debug("");
	log_debug("%s: %lu", __func__, total);
	return (0);
}

static int
h3_end_stream(nghttp3_conn *conn, int64_t stream_id, void *arg, void *sarg)
{
	struct client		*clt = arg;
	struct http_descriptor	*resp = clt->clt_descresp;
	struct nghttp3_data_reader	 dr;

	log_debug("%s", __func__);
	server_response3(httpd_env, clt);
	h3_dyn_nva_reset(&clt->clt_h3dnva);
	if (server_headers(clt, resp, server_writeheader_http3, NULL) == -1)
		return (-1);

        dr.read_data = h3_read_data;
        return nghttp3_conn_submit_response(conn, stream_id,
	    clt->clt_h3dnva.nva, clt->clt_h3dnva.nvlen, &dr);
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

	log_debug("%s ctrl=%llu enc=%llu dec=%llu", __func__, ctrl, enc, dec);

	return (0);
}

void
server_http3conn_free(struct client *clt)
{
	if (clt->clt_h3conn)
		nghttp3_conn_del(clt->clt_h3conn);
	if (clt->clt_h3dnva.nva)
		free(clt->clt_h3dnva.nva);
}

void
server_read_http3(int fd, void *arg)
{
	struct client		*clt = arg;
	int64_t sid = -1;
	uint32_t flags = 0;
	int n, fin;
	uint8_t buf[1500]; /* XXX */

	getmonotime(&clt->clt_tv_last);

/*
	DPRINTF("%s: session %d: size %lu, to read %lld",
	    __func__, clt->clt_id, size, clt->clt_toread);
	if (!size) {
		clt->clt_toread = TOREAD_HTTP_HEADER;
		goto done;
	}
*/

	n = quic_recvmsg(clt->clt_s, &buf, sizeof(buf), &sid, &flags);
	if (n == -1) {
		log_warn("%s quic_recvmsg", __func__);
		goto fail;
	}

	fin = flags & MSG_STREAM_FIN;
	if (nghttp3_conn_read_stream(clt->clt_h3conn, sid, buf, n, fin) < 0) {
		log_warnx("%s nghttp3_conn_read_stream", __func__);
		goto fail;
	}

	if (clt->clt_done) {
		server_close(clt, "done");
		return;
	}
	return;
 fail:
	/* XXX: free the connection */
/*
	server_abort_http3(clt, 500, strerror(errno));
*/
	return;
}

void
server_read_http3content(int fd, void *arg)
{
	struct client		*clt = arg;

	getmonotime(&clt->clt_tv_last);

/*
	DPRINTF("%s: session %d: size %lu, to read %lld", __func__,
	    clt->clt_id, size, clt->clt_toread);
*/

/*
	if (clt->clt_toread > 0) {
		// Read content data
		if ((off_t)size > clt->clt_toread) {
			size = clt->clt_toread;
			if (fcgi_add_stdin(clt, src) == -1)
				goto fail;
			clt->clt_toread = 0;
		} else {
			if (fcgi_add_stdin(clt, src) == -1)
				goto fail;
			clt->clt_toread -= size;
		}
		DPRINTF("%s: done, size %lu, to read %lld", __func__,
		    size, clt->clt_toread);
	}
	if (clt->clt_toread == 0) {
		fcgi_add_stdin(clt, NULL);
		clt->clt_toread = TOREAD_HTTP_HEADER;
		bufferevent_disable(bev, EV_READ);
		bev->readcb = server_read_http;
		return;
	}
	if (clt->clt_done)
		goto done;
	if (bev->readcb != server_read_httpcontent)
		bev->readcb(bev, arg);

*/
	return;
 done:
	return;
 fail:
	server_close(clt, strerror(errno));
}

void
server_read_http3range(struct bufferevent *bev, void *arg)
{
	struct client		*clt = arg;
	struct evbuffer		*src = EVBUFFER_INPUT(bev);
	size_t			 size;
	struct media_type	*media;
	struct range_data	*r = &clt->clt_ranges;
	struct range		*range;

	getmonotime(&clt->clt_tv_last);

	if (r->range_toread > 0) {
		size = EVBUFFER_LENGTH(src);
		if (!size)
			return;

		/* Read chunk data */
		if ((off_t)size > r->range_toread) {
			size = r->range_toread;
			if (server_bufferevent_write_chunk(clt, src, size)
			    == -1)
				goto fail;
			r->range_toread = 0;
		} else {
			if (server_bufferevent_write_buffer(clt, src) == -1)
				goto fail;
			r->range_toread -= size;
		}
		if (r->range_toread < 1)
			r->range_toread = TOREAD_HTTP_RANGE;
		DPRINTF("%s: done, size %lu, to read %lld", __func__,
		    size, r->range_toread);
	}

	switch (r->range_toread) {
	case TOREAD_HTTP_RANGE:
		if (r->range_index >= r->range_count) {
			if (r->range_count > 1) {
				/* Add end marker */
				if (server_bufferevent_printf(clt,
				    "\r\n--%llu--\r\n",
				    clt->clt_boundary) == -1)
					goto fail;
			}
			r->range_toread = TOREAD_HTTP_NONE;
			break;
		}

		range = &r->range[r->range_index];

		if (r->range_count > 1) {
			media = r->range_media;
			if (server_bufferevent_printf(clt,
			    "\r\n--%llu\r\n"
			    "Content-Type: %s/%s\r\n"
			    "Content-Range: bytes %lld-%lld/%zu\r\n\r\n",
			    clt->clt_boundary,
			    media->media_type, media->media_subtype,
			    range->start, range->end, r->range_total) == -1)
				goto fail;
		}
		r->range_toread = range->end - range->start + 1;

		if (lseek(clt->clt_fd, range->start, SEEK_SET) == -1)
			goto fail;

		/* Throw away bytes that are already in the input buffer */
		evbuffer_drain(src, EVBUFFER_LENGTH(src));

		/* Increment for the next part */
		r->range_index++;
		break;
	case TOREAD_HTTP_NONE:
		goto done;
	case 0:
		break;
	}

	if (clt->clt_done)
		goto done;

	if (EVBUFFER_LENGTH(EVBUFFER_OUTPUT(clt->clt_bev)) > (size_t)
	    SERVER_MAX_PREFETCH * clt->clt_sndbufsiz) {
		bufferevent_disable(clt->clt_srvbev, EV_READ);
		clt->clt_srvbev_throttled = 1;
	}

	return;
 done:
	(*bev->errorcb)(bev, EVBUFFER_READ, bev->cbarg);
	return;
 fail:
	server_close(clt, strerror(errno));
}

void
server_abort_http3(struct client *clt, unsigned int code, const char *msg)
{
	struct server_config	*srv_conf = clt->clt_srv_conf;
	struct bufferevent	*bev = clt->clt_bev;
	struct http_descriptor	*desc = clt->clt_descreq;
	const char		*httperr = NULL, *style;
	char			*httpmsg, *body = NULL, *extraheader = NULL;
	char			 tmbuf[32], hbuf[128], *hstsheader = NULL;
	char			*clenheader = NULL;
	char			 buf[IBUF_READ_SIZE];
	char			*escapedmsg = NULL;
	char			 cstr[5];
	ssize_t			 bodylen;

	if (code == 0) {
		server_close(clt, "dropped");
		return;
	}

	if ((httperr = server_httperror_byid(code)) == NULL)
		httperr = "Unknown Error";

	if (bev == NULL)
		goto done;

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
		if (asprintf(&extraheader, "Location: %s\r\n", buf) == -1) {
			code = 500;
			extraheader = NULL;
		}
		msg = buf;
		break;
	case 401:
		if (msg == NULL)
			break;
		if (stravis(&escapedmsg, msg, VIS_DQ) == -1) {
			code = 500;
			extraheader = NULL;
		} else if (asprintf(&extraheader,
		    "WWW-Authenticate: Basic realm=\"%s\"\r\n", escapedmsg)
		    == -1) {
			code = 500;
			extraheader = NULL;
		}
		break;
	case 416:
		if (msg == NULL)
			break;
		if (asprintf(&extraheader,
		    "Content-Range: %s\r\n", msg) == -1) {
			code = 500;
			extraheader = NULL;
		}
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
	if (srv_conf->flags & SRVFLAG_SERVER_HSTS &&
	    srv_conf->flags & SRVFLAG_TLS) {
		if (asprintf(&hstsheader, "Strict-Transport-Security: "
		    "max-age=%d%s%s\r\n", srv_conf->hsts_max_age,
		    srv_conf->hsts_flags & HSTSFLAG_SUBDOMAINS ?
		    "; includeSubDomains" : "",
		    srv_conf->hsts_flags & HSTSFLAG_PRELOAD ?
		    "; preload" : "") == -1) {
			hstsheader = NULL;
			goto done;
		}
	}

	if ((code >= 100 && code < 200) || code == 204)
		clenheader = NULL;
	else {
		if (asprintf(&clenheader,
		    "Content-Length: %zd\r\n", bodylen) == -1) {
			clenheader = NULL;
			goto done;
		}
	}

	/* Add basic HTTP headers */
	if (asprintf(&httpmsg,
	    "HTTP/1.0 %03d %s\r\n"
	    "Date: %s\r\n"
	    "Server: %s\r\n"
	    "Connection: close\r\n"
	    "Content-Type: text/html\r\n"
	    "%s"
	    "%s"
	    "%s"
	    "\r\n"
	    "%s",
	    code, httperr, tmbuf, HTTPD_SERVERNAME,
	    clenheader == NULL ? "" : clenheader,
	    extraheader == NULL ? "" : extraheader,
	    hstsheader == NULL ? "" : hstsheader,
	    desc->http_method == HTTP_METHOD_HEAD || clenheader == NULL ?
	    "" : body) == -1)
		goto done;

	/* Dump the message without checking for success */
	server_dump(clt, httpmsg, strlen(httpmsg));
	free(httpmsg);

 done:
	free(body);
	free(extraheader);
	free(hstsheader);
	free(clenheader);
	if (msg == NULL)
		msg = "\"\"";
	if (asprintf(&httpmsg, "%s (%03d %s)", msg, code, httperr) == -1) {
		server_close(clt, msg);
	} else {
		server_close(clt, httpmsg);
		free(httpmsg);
	}
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

	/*
	 * Do we have a Host header and matching configuration?
	 * XXX: is this necessary for H3?
	 */
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
        char                   	*ptr;
        const char             	*key;

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
server_response_http3(struct evbuffer *buf, size_t old, size_t now, void *arg)
{
	struct client		*clt = arg;
        DPRINTF("%s: hallo", __func__);
}
