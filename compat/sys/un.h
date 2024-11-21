/*
 * Public domain
 * sys/types.h compatibility shim
 */

#ifndef _MSC_VER
#include_next <sys/un.h>
#else

#ifndef HTTPD_COMPAT_SYS_UN_H
#define HTTPD_COMPAT_SYS_UN_H

#include <afunix.h>

#endif /* !HTTPD_COMPAT_SYS_UN_H */
#endif
