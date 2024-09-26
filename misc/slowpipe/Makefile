#	$OpenBSD$

.include <bsd.own.mk>
.include <bsd.obj.mk>

PROG=	slowpipe
NOMAN=

SSHREL=../../../../../usr.bin/ssh
.PATH: ${.CURDIR}/${SSHREL}

OPENSSL?=	no

.if (${OPENSSL:L} == "yes")
CFLAGS+=	-DWITH_OPENSSL
.endif

# enable warnings
WARNINGS=Yes

DEBUG=-g
CFLAGS+=	-fstack-protector-all
CDIAGFLAGS=	-Wall
CDIAGFLAGS+=	-Wextra
CDIAGFLAGS+=	-Werror
CDIAGFLAGS+=	-Wchar-subscripts
CDIAGFLAGS+=	-Wcomment
CDIAGFLAGS+=	-Wformat
CDIAGFLAGS+=	-Wformat-security
CDIAGFLAGS+=	-Wimplicit
CDIAGFLAGS+=	-Winline
CDIAGFLAGS+=	-Wmissing-declarations
CDIAGFLAGS+=	-Wmissing-prototypes
CDIAGFLAGS+=	-Wparentheses
CDIAGFLAGS+=	-Wpointer-arith
CDIAGFLAGS+=	-Wreturn-type
CDIAGFLAGS+=	-Wshadow
CDIAGFLAGS+=	-Wsign-compare
CDIAGFLAGS+=	-Wstrict-aliasing
CDIAGFLAGS+=	-Wstrict-prototypes
CDIAGFLAGS+=	-Wswitch
CDIAGFLAGS+=	-Wtrigraphs
CDIAGFLAGS+=	-Wuninitialized
CDIAGFLAGS+=	-Wunused
CDIAGFLAGS+=	-Wno-unused-parameter
.if ${COMPILER_VERSION:L} != "gcc3"
CDIAGFLAGS+=	-Wold-style-definition
.endif

CFLAGS+=-I${.CURDIR}/${SSHREL}

.if (${OPENSSL:L} == "yes")
LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}
.endif

# From usr.bin/ssh/Makefile.inc
SRCS=	slowpipe.c
SRCS+=	sshbuf.c
SRCS+=	sshbuf-getput-basic.c
SRCS+=	sshbuf-misc.c
SRCS+=	ssherr.c
SRCS+=	log.c
SRCS+=	fatal.c
SRCS+=	cleanup.c
SRCS+=	xmalloc.c
SRCS+=	misc.c
SRCS+=	match.c
SRCS+=	addr.c
SRCS+=	addrmatch.c

.include <bsd.prog.mk>

