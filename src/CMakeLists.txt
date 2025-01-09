# Copyright (c) 2024 Moritz Buhl <mbuhl@openbsd.org>
# Copyright (c) 2020-2021 Tobias Heider <tobhe@openbsd.org>
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

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckIncludeFiles)

set(VERSIONED_FILES)
list(APPEND VERSIONED_FILES iked.c)

set(SRCS)
set(LIBS)

set(CFLAGS)
list(APPEND CFLAGS
	-O2
	-fstack-protector-strong
	-fPIE
	-D_FORTIFY_SOURCE=2
	-Wall
	-Wno-pointer-sign
	-Wno-deprecated-declarations
	-Wstrict-prototypes
	-Wmissing-prototypes
	-Wmissing-declarations
	-Wshadow
	-Wpointer-arith
	-Wcast-qual
	-Wsign-compare
	"$<$<CONFIG:DEBUG>:-O0;-g>"
)

set(INC_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

list(APPEND SRCS
	config.c
	control.c
	httpd.c
	log.c
	logger.c
	patterns.c
	proc.c
	server.c
	server_fcgi.c
	server_file.c
	server_http.c
	# Generated files
	${CMAKE_CURRENT_BINARY_DIR}/parse.c
)

add_executable(httpd ${SRCS})

target_compile_options(httpd PRIVATE ${CFLAGS})
if(HAVE_LD_Z)
	target_link_options(httpd PRIVATE "LINKER:-z,relro,-z,now")
endif()

target_include_directories(httpd PRIVATE ${INC_DIRS})

list(APPEND LIBS
	util
	event
	crypto
	ssl
	tls
	compat
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND LIBS
		resolv
		crypt
	)
endif()

if(HAVE_NETINET_QUIC_H)
	list(APPEND LIBS
		quic
	)
endif()

target_link_libraries(httpd
	PRIVATE ${LIBS}
)

add_custom_command(
	OUTPUT parse.c
	COMMAND yacc -o parse.c ${CMAKE_CURRENT_SOURCE_DIR}/parse.y
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parse.y
)

add_custom_command(
	OUTPUT css.h
	COMMAND sed -f ${CMAKE_CURRENT_SOURCE_DIR}/toheader.sed <
            ${CMAKE_CURRENT_SOURCE_DIR}/css.h.in > css.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/css.h.in
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/toheader.sed
)

add_custom_command(
	OUTPUT js.h
	COMMAND sed -f ${CMAKE_CURRENT_SOURCE_DIR}/toheader.sed <
            ${CMAKE_CURRENT_SOURCE_DIR}/js.h.in > js.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/js.h.in
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/toheader.sed
)

add_custom_target(
	genhdrs
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/css.h ${CMAKE_CURRENT_BINARY_DIR}/js.h
)

add_dependencies(httpd genhdrs)

if(NOT DEFINED CMAKE_INSTALL_FULL_LOCALSTATEDIR)
  set(CMAKE_INSTALL_FULL_LOCALSTATEDIR /var) # XXX
endif()

install(TARGETS httpd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES ${CMAKE_SOURCE_DIR}/httpd.conf
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/httpd.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/httpd.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)

install(DIRECTORY
	DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/www/cache
)
install(CODE "
	execute_process(
		COMMAND chown www ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/www/cache
	)
")

set(WWW_DIRS)
list(APPEND WWW_DIRS
	www
	www/acme
	www/bin
	www/cgi-bin
	www/conf
	www/htdocs
	www/logs
	www/run
)

foreach(dir ${WWW_DIRS})
	install(DIRECTORY
		DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/${dir}
	)
endforeach()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/empty" "")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/empty"
        DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/www/logs
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        RENAME access.log
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/empty"
        DESTINATION ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/www/logs
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        RENAME error.log
)
