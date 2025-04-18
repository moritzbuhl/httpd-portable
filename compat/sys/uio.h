/*
 * Public domain
 * sys/uio.h compatibility shim
 */

#ifndef _MSC_VER
#include_next <sys/uio.h>
#else

#ifndef HTTPD_COMPAT_SYS_UIO_H
#define HTTPD_COMPAT_SYS_UIO_H

#define	IOV_MAX	16	/* XXX */

struct iovec {
	void    *iov_base;      /* Base address. */
	size_t   iov_len;       /* Length. */
};

/* needs to be converted to WSABUF with buf/len attributes */

#endif /* !HTTPD_COMPAT_SYS_UIO_H */

#endif
