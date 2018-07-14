PROG=	macwatchd
SRCS=	macwatchd.c log.c
CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=
DPADD+=	${LIBUTIL}
MAN=

.include <bsd.prog.mk>

