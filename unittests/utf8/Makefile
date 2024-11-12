#	$OpenBSD: Makefile,v 1.5 2017/12/21 00:41:22 djm Exp $

PROG=test_utf8
SRCS=tests.c

# From usr.bin/ssh
SRCS+=utf8.c atomicio.c misc.c xmalloc.c match.c ssherr.c cleanup.c fatal.c
SRCS+=sshbuf.c sshbuf-getput-basic.c sshbuf-misc.c addr.c addrmatch.c log.c

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG} ${UNITTEST_ARGS}

.include <bsd.regress.mk>
