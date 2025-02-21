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
int		 server_response_http3(struct client *, unsigned int,
		    struct media_type *, off_t, time_t);
int		 server_http_authenticate(struct server_config *,
		    struct client *);
void		 server_read_http3range(struct bufferevent *, void *);

void
server_http3(void)
{
	/* nothing */
}

int
server_http3conn_init(struct client *clt)
{
	int64_t ctrl_sid, qpk_enc_sid, qpk_dec_sid;
	struct quic_transport_param param = {};
	nghttp3_callbacks callbacks = {
/*
		http_acked_stream_data,
		http_stream_close,
		http_recv_data,
		http_deferred_consume,
		http_server_begin_headers,
		http_server_recv_header,
		http_end_headers,
		http_begin_trailers,
		http_recv_trailer,
		http_end_trailers,
		http_stop_sending,
		http_server_end_stream,
		http_reset_stream,
		http_shutdown,
		http_recv_settings,
*/
	};
	struct quic_stream_info si;
	socklen_t len = sizeof(si);
	nghttp3_settings settings;
	unsigned int plen;

	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	if (nghttp3_conn_server_new(&(clt->clt_h3conn), &callbacks, &settings,
	    NULL, NULL))
		return (-1);

/*
	plen = sizeof(param);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param,
	    &plen) == -1) {
		http_log_error("socket getsockopt remote transport param\n");
		return (-1);
	}
	nghttp3_conn_set_max_client_streams_bidi(clt->clt_h3conn,
	    param.max_streams_bidi);

	si.stream_id = -1;
	si.stream_flags = MSG_STREAM_UNI;
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &si, &len)) {
		http_log_error("socket getsockopt stream_open ctrl failed\n");
		return (-1);
	}
	ctrl_sid = si.stream_id;
	if (nghttp3_conn_bind_control_stream(clt->clt_h3conn, ctrl_sid))
		return (-1);
	http_log_debug("%s ctrl_stream_id %llu\n", __func__, ctrl_sid);

	si.stream_id = -1;
	si.stream_flags = MSG_STREAM_UNI;
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &si, &len)) {
		http_log_error("socket getsockopt stream_open enc failed\n");
		return (-1);
	}
	qpk_enc_sid = si.stream_id;
	http_log_debug("%s qpack_enc_stream_id %llu\n", __func__, qpk_enc_sid);

	si.stream_id = -1;
	si.stream_flags = MSG_STREAM_UNI;
	if(getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &si, &len)) {
		http_log_error("socket getsockopt stream_open dec failed\n");
		return (-1);
	}
	qpk_dec_sid = si.stream_id;
	http_log_debug("%s qpack_dec_stream_id %llu\n", __func__, qpk_dec_sid);
	if (nghttp3_conn_bind_qpack_streams(clt->clt_h3conn, qpk_enc_sid,
	    qpk_dec_sid))
		return (-1);
*/
	return (0);
}

void
server_http3conn_free(struct client *clt)
{
	nghttp3_conn_del(clt->clt_h3conn);
}


void
server_read_http3(int fd, void *arg)
{
	struct client		*clt = arg;

	getmonotime(&clt->clt_tv_last);

/*
	DPRINTF("%s: session %d: size %lu, to read %lld",
	    __func__, clt->clt_id, size, clt->clt_toread);
	if (!size) {
		clt->clt_toread = TOREAD_HTTP_HEADER;
		goto done;
	}
*/

/*
	if (nghttp3_conn_read_stream(clt->clt_h3conn, stream_id, buf, ret,
				       flags & MSG_STREAM_FIN) .... ) {
	if (ret < 0)
		return -1;
*/

	if (clt->clt_done) {
		server_close(clt, "done");
		return;
	}
	return;
 fail:
	server_abort_http3(clt, 500, strerror(errno));
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
server_reset_http3(struct client *clt)
{
	struct server		*srv = clt->clt_srv;

	server_log(clt, NULL);

	server_http3conn_free(clt);
	server_httpdesc_free(clt->clt_descreq);
	server_httpdesc_free(clt->clt_descresp);
	clt->clt_headerlen = 0;
	clt->clt_headersdone = 0;
	clt->clt_done = 0;
	clt->clt_line = 0;
	clt->clt_chunk = 0;
	free(clt->clt_remote_user);
	clt->clt_remote_user = NULL;
	clt->clt_bev->readcb = server_read_http;
	clt->clt_srv_conf = &srv->srv_conf;
	str_match_free(&clt->clt_srv_match);
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
/* XXX
		if (server_expand_http(clt, msg, buf, sizeof(buf)) == NULL)
			goto done;
*/
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
	struct http_descriptor *desc;

	server_http3conn_free(clt);
	clt->clt_h3conn = NULL;
	desc = clt->clt_descreq;
	server_httpdesc_free(desc);
	free(desc);
	clt->clt_descreq = NULL;

	desc = clt->clt_descresp;
	server_httpdesc_free(desc);
	free(desc);
	clt->clt_descresp = NULL;
	free(clt->clt_remote_user);
	clt->clt_remote_user = NULL;

	str_match_free(&clt->clt_srv_match);
}

int
server_response_http3(struct client *clt, unsigned int code,
    struct media_type *media, off_t size, time_t mtime)
{
	struct server_config	*srv_conf = clt->clt_srv_conf;
	struct http_descriptor	*desc = clt->clt_descreq;
	struct http_descriptor	*resp = clt->clt_descresp;
	const char		*error;
	struct kv		*ct, *cl;
	char			 tmbuf[32];

	if (desc == NULL || media == NULL ||
	    (error = server_httperror_byid(code)) == NULL)
		return (-1);

	if (server_log_http(clt, code, size >= 0 ? size : 0) == -1)
		return (-1);

	/* Add error codes */
	if (kv_setkey(&resp->http_pathquery, "%u", code) == -1 ||
	    kv_set(&resp->http_pathquery, "%s", error) == -1)
		return (-1);

	/* Add headers */
	if (kv_add(&resp->http_headers, "Server", HTTPD_SERVERNAME) == NULL)
		return (-1);

	/* Is it a persistent connection? */
	if (clt->clt_persist) {
		if (kv_add(&resp->http_headers,
		    "Connection", "keep-alive") == NULL)
			return (-1);
	} else if (kv_add(&resp->http_headers, "Connection", "close") == NULL)
		return (-1);

	/* Set media type */
	if ((ct = kv_add(&resp->http_headers, "Content-Type", NULL)) == NULL ||
	    kv_set(ct, "%s/%s", media->media_type, media->media_subtype) == -1)
		return (-1);

	/* Set content length, if specified */
	if (size >= 0 && ((cl =
	    kv_add(&resp->http_headers, "Content-Length", NULL)) == NULL ||
	    kv_set(cl, "%lld", (long long)size) == -1))
		return (-1);

	/* Set last modification time */
	if (server_http_time(mtime, tmbuf, sizeof(tmbuf)) <= 0 ||
	    kv_add(&resp->http_headers, "Last-Modified", tmbuf) == NULL)
		return (-1);

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
			return (-1);
	}

	/* Date header is mandatory and should be added as late as possible */
	if (server_http_time(time(NULL), tmbuf, sizeof(tmbuf)) <= 0 ||
	    kv_add(&resp->http_headers, "Date", tmbuf) == NULL)
		return (-1);

	/* Write completed header */
	if (server_writeresponse_http(clt) == -1 ||
	    server_bufferevent_print(clt, "\r\n") == -1 ||
	    server_headers(clt, resp, server_writeheader_http, NULL) == -1 ||
	    server_bufferevent_print(clt, "\r\n") == -1)
		return (-1);

	if (size <= 0 || resp->http_method == HTTP_METHOD_HEAD) {
		bufferevent_enable(clt->clt_bev, EV_READ|EV_WRITE);
		if (clt->clt_persist)
			clt->clt_toread = TOREAD_HTTP_HEADER;
		else
			clt->clt_toread = TOREAD_HTTP_NONE;
		clt->clt_done = 0;
		return (0);
	}

	return (1);
}
