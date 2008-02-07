CC?=	gcc
CFLAGS+=-I../siplog
LIBS+=	-L../siplog -lsiplog

# Uncomment this on Solaris
#LIBS+=	-lresolv -lsocket -lnsl

all: rtpproxy

rtpproxy: main.o rtp_server.o rtpp_record.o rtpp_util.o rtp_resizer.o rtp.o
	${CC} -o rtpproxy main.o rtp_server.o rtpp_record.o rtpp_util.o rtp_resizer.o rtp.o ${LIBS}

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

clean:
	rm -f main.o rtp_server.o rtpp_record.o rtpp_util.o rtpproxy
