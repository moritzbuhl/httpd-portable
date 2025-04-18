/* Placed in the public domain */

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#define YYSTYPE_IS_DECLARED 1	/* for bison */

#ifndef LOGIN_NAME_MAX
# define LOGIN_NAME_MAX 9
#endif

#include <stdlib.h>

#if !defined(HAVE_CRYPT_CHECKPASS)
int crypt_checkpass(const char *, const char *);
#endif

#if !defined(HAVE_STRLCAT)
size_t strlcat(char *, const char *, size_t);
#endif

#if !defined(HAVE_STRLCPY)
size_t strlcpy(char *, const char *, size_t);
#endif

#if !defined(HAVE_REALLOCARRAY)
void *reallocarray(void *, size_t, size_t);
#endif

#if !defined(HAVE_RECALLOCARRAY)
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#if !defined(HAVE_EXPLICIT_BZERO)
void explicit_bzero(void *, size_t);
#endif

#if !defined(HAVE_GETPAGESIZE)
int getpagesize(void);
#endif

#if !defined(HAVE_TIMINGSAFE_BCMP)
int timingsafe_bcmp(const void *, const void *, size_t);
#endif

#if !defined(HAVE_ACCEPT4)
#include <sys/socket.h>
#define accept4 bsd_accept4
int bsd_accept4(int, struct sockaddr *, socklen_t *, int flags);
#endif

#if !defined(HAVE_SOCK_NONBLOCK)
#define SOCK_NONBLOCK	0x4000	/* Set O_NONBLOCK */
#define SOCK_CLOEXEC	0x8000	/* Set FD_CLOEXEC */
#define SOCK_SETFLAGS	0xf000	/* Set flags as checked above */
#define socket bsd_socket
int bsd_socket(int domain, int type, int protocol);
#endif

#if !defined(HAVE_SETPROCTITLE)
void compat_init_setproctitle(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);
#endif

#if !defined(HAVE_SETRESGID)
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#endif

#if !defined(HAVE_SETRESUID)
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#endif

#ifdef _WIN32
#include <direct.h>
uid_t geteuid(void);
#endif

#if !defined(HAVE_GETRTABLE)
int getrtable(void);
#endif

#if !defined(HAVE_SETRTABLE)
int setrtable(int rtableid);
#endif

#if !defined(HAVE_STRTONUM)
long long
strtonum(const char *nptr, long long minval, long long maxval,
    const char **errstr);
#endif

#if !defined(HAVE_FREEZERO)
void freezero(void *ptr, size_t size);
#endif

#if !defined(HAVE_GETDTABLECOUNT)
int getdtablecount(void);
#endif

#if !defined(HAVE_GETOPT)
#include "getopt.h"
#endif

#if !defined(HAVE_USLEEP)
int usleep(unsigned int x);
#endif

#ifdef HAVE_SOCKADDR_SA_LEN
#ifndef SA_LEN
#define SA_LEN(sa)      (sa)->sa_len
#endif
#ifndef SS_LEN
#define SS_LEN(ss)      (ss)->ss_len
#endif
#else
#define SA_LEN(sa)      						\
	((sa->sa_family == AF_INET)  ? sizeof(struct sockaddr_in) :	\
	(sa->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) :	\
	sizeof(struct sockaddr))
#define SS_LEN(ss)							\
	((ss->ss_family == AF_INET)  ? sizeof(struct sockaddr_in) :	\
	(ss->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) :	\
	sizeof(struct sockaddr_storage))
#endif

#ifndef HAVE_FFS
int ffs(int);
#endif

#ifdef __OpenBSD__
typedef int evutil_socket_t;
#endif

#ifndef _PASSWORD_LEN
#define _PASSWORD_LEN	120
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#if !defined(AF_LINK) && defined(AF_PACKET)
#define AF_LINK AF_PACKET	/* XXX workaround on Linux */
#endif

#ifndef HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# if defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# else
#  define HOST_NAME_MAX 255
# endif
#endif /* HOST_NAME_MAX */

#if !defined(__packed)
#define __packed	__attribute__((__packed__))
#endif
#if !defined(__unused)
#define __unused	__attribute__((__unused__))
#endif

#if !defined(timespeccmp)
#define timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

/* if PATH_MAX is too large, struct server_config outgrows MAX_IMSGSIZE */
#undef PATH_MAX
#define PATH_MAX	1024

#endif /* !_OPENBSD_COMPAT_H */
