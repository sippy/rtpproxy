CC?=	gcc
CFLAGS+=-I../siplog
LIBS+=	-L../siplog -lsiplog -lpthread
PREFIX?= /usr/local

# Uncomment this on Solaris
#LIBS+=	-lresolv -lsocket -lnsl

all: rtpproxy

rtpproxy: main.o rtp_server.o rtpp_record.o rtpp_util.o rtp_resizer.o rtp.o rtpp_session.o rtpp_command.o
	${CC} -o rtpproxy main.o rtp_server.o rtpp_record.o rtpp_util.o rtp_resizer.o rtp.o rtpp_session.o rtpp_command.o ${LIBS}

main.o: main.c
	${CC} ${CFLAGS} -o main.o -c main.c

rtp_server.o: rtp_server.c
	${CC} ${CFLAGS} -o rtp_server.o -c rtp_server.c

rtpp_record.o: rtpp_record.c
	${CC} ${CFLAGS} -o rtpp_record.o -c rtpp_record.c

rtpp_util.o: rtpp_util.c
	${CC} ${CFLAGS} -o rtpp_util.o -c rtpp_util.c

rtp_resizer.o: rtp_resizer.c
	${CC} ${CFLAGS} -o rtp_resizer.o -c rtp_resizer.c

rtp.o: rtp.c
	${CC} ${CFLAGS} -o rtp.o -c rtp.c

rtpp_session.o: rtpp_session.c
	${CC} ${CFLAGS} -o rtpp_session.o -c rtpp_session.c

rtpp_command.o: rtpp_command.c
	${CC} ${CFLAGS} -o rtpp_command.o -c rtpp_command.c

clean:
	rm -f main.o rtp_server.o rtpp_record.o rtpp_util.o rtp_resizer.o rtp.o rtpp_session.o rtpp_command.o rtpproxy

install: all
	install rtpproxy ${PREFIX}/bin/rtpproxy
