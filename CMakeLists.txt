# Copyright (c) 2024 Moritz Buhl <mbuhl@openbsd.org>
# Copyright (c) 2020-2022 Tobias Heider <tobhe@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

cmake_minimum_required(VERSION 3.12)

project(httpd)

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckIncludeFiles)
include(CheckLinkerFlag)

set(CMAKE_REQUIRED_LIBRARIES util)
set(CMAKE_REQUIRED_DEFINITIONS -D__BSD_VISIBLE)

include_directories("/usr/local/include")
link_directories("/usr/local/lib")

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	if (NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
		set (CMAKE_INSTALL_SYSCONFDIR ${CMAKE_INSTALL_PREFIX}/etc)
	endif()
	add_definitions(-DHTTPD_CONFIG="${CMAKE_INSTALL_SYSCONFDIR}/httpd.conf")
	add_definitions(-DHAVE_SOCKADDR_SA_LEN)
	if (HOMEBREW AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64")
		include_directories("/opt/homebrew/include")
		link_directories("/opt/homebrew/lib")
		include_directories("/opt/homebrew/opt/openssl/include")
		link_directories("/opt/homebrew/opt/openssl/lib")
	else()
		include_directories("/usr/local/opt/openssl/include")
		link_directories("/usr/local/opt/openssl/lib")
	endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
	if (NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
		set (CMAKE_INSTALL_SYSCONFDIR /etc)
	endif()
	add_definitions(-DHAVE_ATTRIBUTE__BOUNDED__)
	add_definitions(-DHAVE_ATTRIBUTE__DEAD__)
	add_definitions(-DHAVE_SOCKADDR_SA_LEN)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	if (NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
		set (CMAKE_INSTALL_SYSCONFDIR ${CMAKE_INSTALL_PREFIX}/etc)
	endif()
	add_definitions(-DHTTPD_CONFIG="${CMAKE_INSTALL_SYSCONFDIR}/httpd.conf")
	add_definitions(-DHAVE_SOCKADDR_SA_LEN)
elseif(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	if (NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
		set (CMAKE_INSTALL_SYSCONFDIR /etc)
	endif()
	add_definitions(-DHAVE_SOCKADDR_SA_LEN)
	add_definitions(-D_OPENBSD_SOURCE)
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if (NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
		set (CMAKE_INSTALL_SYSCONFDIR /etc)
	endif()
	if (NOT DEFINED CMAKE_INSTALL_MANDIR)
		set (CMAKE_INSTALL_MANDIR /usr/share/man)
	endif()
	add_definitions(-D_GNU_SOURCE)
	add_definitions(-D_DEFAULT_SOURCE)
	add_definitions(-DSPT_TYPE=SPT_REUSEARGV)
endif()
if (NOT DEFINED CMAKE_INSTALL_MANDIR)
	set (CMAKE_INSTALL_MANDIR ${CMAKE_INSTALL_PREFIX}/man)
endif()
if (NOT DEFINED CMAKE_INSTALL_SBINDIR)
	set (CMAKE_INSTALL_SBINDIR ${CMAKE_INSTALL_PREFIX}/sbin)
endif()

check_linker_flag(C "LINKER:-z,now,-z,relro" HAVE_LD_Z)

if(CMAKE_BUILD_TYPE STREQUAL DEBUG)
	message("Debug build.")
	add_definitions(-DDEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL RELEASE)
	message("Release build.")
endif()

check_include_files(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
	add_definitions(-DHAVE_UNISTD_H)
endif()

check_include_files(endian.h HAVE_ENDIAN_H)
if(HAVE_ENDIAN_H)
	add_definitions(-DHAVE_ENDIAN_H)
endif()

check_include_files(dirent.h HAVE_DIRENT_H)
if(HAVE_DIRENT_H)
	add_definitions(-DHAVE_DIRENT_H)
endif()

check_include_files(grp.h HAVE_GRP_H)
if(HAVE_GRP_H)
	add_definitions(-DHAVE_GRP_H)
endif()

check_include_files("sys/types.h;sys/queue.h;imsg.h" HAVE_IMSG_H)
if(HAVE_IMSG_H)
	add_definitions(-DHAVE_IMSG_H)
endif()

check_function_exists(recallocarray HAVE_RECALLOCARRAY)
if(HAVE_RECALLOCARRAY)
	add_definitions(-DHAVE_RECALLOCARRAY)
endif()

check_function_exists(reallocarray HAVE_REALLOCARRAY)
if(HAVE_REALLOCARRAY)
	add_definitions(-DHAVE_REALLOCARRAY)
endif()

check_function_exists(accept4 HAVE_ACCEPT4)
if(HAVE_ACCEPT4)
	add_definitions(-DHAVE_ACCEPT4)
endif()

check_symbol_exists(SOCK_NONBLOCK "sys/socket.h" HAVE_SOCK_NONBLOCK)
if(HAVE_SOCK_NONBLOCK)
	add_definitions(-DHAVE_SOCK_NONBLOCK)
endif()

check_function_exists(setproctitle HAVE_SETPROCTITLE)
if(HAVE_SETPROCTITLE)
	add_definitions(-DHAVE_SETPROCTITLE)
endif()

check_function_exists(pledge HAVE_PLEDGE)
if(HAVE_PLEDGE)
	add_definitions(-DHAVE_PLEDGE)
endif()

check_function_exists(setresgid HAVE_SETRESGID)
if(HAVE_SETRESGID)
	add_definitions(-DHAVE_SETRESGID)
endif()

check_function_exists(setresuid HAVE_SETRESUID)
if(HAVE_SETRESUID)
	add_definitions(-DHAVE_SETRESUID)
endif()

check_function_exists(setregid HAVE_SETREGID)
if(HAVE_SETREGID)
	add_definitions(-DHAVE_SETREGID)
endif()

check_function_exists(setreuid HAVE_SETREUID)
if(HAVE_SETREUID)
	add_definitions(-DHAVE_SETREUID)
endif()

check_function_exists(strtonum HAVE_STRTONUM)
if(HAVE_STRTONUM)
	add_definitions(-DHAVE_STRTONUM)
endif()

check_symbol_exists(TCP_SACK_ENABLE "sys/types.h;netinet/tcp.h" HAVE_TCP_SACK_ENABLE)
if(HAVE_TCP_SACK_ENABLE)
	add_definitions(-DHAVE_TCP_SACK_ENABLE)
endif()

check_struct_has_member("struct ifgroupreq" ifgr_name "net/if.h" HAVE_IFGROUPREQ)
if(HAVE_IFGROUPREQ)
	add_definitions(-DHAVE_IFGROUPREQ)
endif()

check_function_exists(freezero HAVE_FREEZERO)
if(HAVE_FREEZERO)
	add_definitions(-DHAVE_FREEZERO)
endif()

check_function_exists(getdtablecount HAVE_GETDTABLECOUNT)
if(HAVE_GETDTABLECOUNT)
	add_definitions(-DHAVE_GETDTABLECOUNT)
endif()

check_symbol_exists(timespecsub "sys/time.h" HAVE_TIMESPECSUB)
if(HAVE_TIMESPECSUB)
	add_definitions(-DHAVE_TIMESPECSUB)
endif()

check_function_exists(asprintf HAVE_ASPRINTF)
if(HAVE_ASPRINTF)
	add_definitions(-DHAVE_ASPRINTF)
endif()

check_function_exists(strcasecmp HAVE_STRCASECMP)
if(HAVE_STRCASECMP)
	add_definitions(-DHAVE_STRCASECMP)
endif()

check_function_exists(strlcat HAVE_STRLCAT)
if(HAVE_STRLCAT)
	add_definitions(-DHAVE_STRLCAT)
endif()

check_function_exists(strlcpy HAVE_STRLCPY)
if(HAVE_STRLCPY)
	add_definitions(-DHAVE_STRLCPY)
endif()

check_function_exists(strndup HAVE_STRNDUP)
if(HAVE_STRNDUP)
	add_definitions(-DHAVE_STRNDUP)
endif()

check_function_exists(ffs HAVE_FFS)
if(HAVE_FFS)
	add_definitions(-DHAVE_FFS)
endif()

check_function_exists(fmt_scaled HAVE_FMT_SCALED)
if(HAVE_FMT_SCALED)
	add_definitions(-DHAVE_FMT_SCALED)
endif()

check_function_exists(strnlen HAVE_STRNLEN)
if(HAVE_STRNLEN)
	add_definitions(-DHAVE_STRNLEN)
endif()

check_function_exists(strsep HAVE_STRSEP)
if(HAVE_STRSEP)
	add_definitions(-DHAVE_STRSEP)
endif()

check_function_exists(timegm HAVE_TIMEGM)
if(HAVE_TIMEGM)
	add_definitions(-DHAVE_TIMEGM)
endif()

check_function_exists(arc4random_buf HAVE_ARC4RANDOM_BUF)
if(HAVE_ARC4RANDOM_BUF)
	add_definitions(-DHAVE_ARC4RANDOM_BUF)
endif()

check_function_exists(arc4random_uniform HAVE_ARC4RANDOM_UNIFORM)
if(HAVE_ARC4RANDOM_UNIFORM)
	add_definitions(-DHAVE_ARC4RANDOM_UNIFORM)
endif()

check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
	add_definitions(-DHAVE_EXPLICIT_BZERO)
endif()

check_function_exists(getentropy HAVE_GETENTROPY)
if(HAVE_GETENTROPY)
	add_definitions(-DHAVE_GETENTROPY)
endif()

check_symbol_exists(getpagesize unistd.h HAVE_GETPAGESIZE)
if(HAVE_GETPAGESIZE)
	add_definitions(-DHAVE_GETPAGESIZE)
endif()

check_function_exists(vis HAVE_VIS)
if(HAVE_VIS)
	add_definitions(-DHAVE_VIS)
endif()

check_symbol_exists(timespecsub sys/time.h HAVE_TIMESPECSUB)
if(HAVE_TIMESPECSUB)
	add_definitions(-DHAVE_TIMESPECSUB)
endif()

check_function_exists(timingsafe_bcmp HAVE_TIMINGSAFE_BCMP)
if(HAVE_TIMINGSAFE_BCMP)
	add_definitions(-DHAVE_TIMINGSAFE_BCMP)
endif()

check_function_exists(timingsafe_memcmp HAVE_TIMINGSAFE_MEMCMP)
if(HAVE_MEMCMP)
	add_definitions(-DHAVE_MEMCMP)
endif()

check_function_exists(memmem HAVE_MEMMEM)
if(HAVE_MEMMEM)
	add_definitions(-DHAVE_MEMMEM)
endif()

check_include_files(err.h HAVE_ERR_H)
if(HAVE_ERR_H)
	add_definitions(-DHAVE_ERR_H)
endif()

check_include_files(crypt.h HAVE_CRYPT_H)
if(HAVE_CRYPT_H)
	add_definitions(-DHAVE_CRYPT_H)
endif()

check_function_exists(crypt_checkpass HAVE_CRYPT_CHECKPASS)
if(HAVE_CRYPT_CHECKPASS)
	add_definitions(-DHAVE_CRYPT_CHECKPASS)
endif()

check_function_exists(usleep HAVE_USLEEP)
if(HAVE_USLEEP)
	add_definitions(-DHAVE_USLEEP)
endif()

check_function_exists(getopt HAVE_GETOPT)
if(HAVE_GETOPT)
	add_definitions(-DHAVE_GETOPT)
endif()

check_function_exists(msgbuf_new_reader HAVE_MSGBUF_NEW_READER)
if(HAVE_MSGBUF_NEW_READER)
	add_definitions(-DHAVE_MSGBUF_NEW_READER)
endif()

check_symbol_exists(LIBEVENT_VERSION_NUMBER "event.h" HAVE_LIBEVENT2)
if(HAVE_LIBEVENT2)
	add_definitions(-DHAVE_LIBEVENT2)
endif()

if(ASAN)
	message("Using ASAN")
	string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -fsanitize=address")
	string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -fsanitize=address")
endif()
if(UBSAN)
	message("Using UBSAN")
	string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -fsanitize=undefined")
	string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -fsanitize=undefined")
endif()
if(MSAN)
	message("Using MSAN")
	string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -fsanitize=memory")
	string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -fsanitize=memory")
endif()

install(CODE "
	execute_process(
		COMMAND getent passwd www
		RESULT_VARIABLE USER_EXISTS
		OUTPUT_QUIET
		ERROR_QUIET
	)
	if(NOT USER_EXISTS EQUAL 0)
		message(FATAL_ERROR
			\"User 'www' required for installation.\n\"
			\"useradd -s /usr/sbin/nologin -d /var/www www\" # XXX
		)
	endif()
")


add_subdirectory(compat)
add_subdirectory(quic)
add_subdirectory(src)
