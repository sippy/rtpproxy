CC?=	gcc

# Uncomment this on Solaris
#LIBS=	-lresolv

all: rtpproxy

rtpproxy: main.o
	${CC} -o rtpproxy main.o ${LIBS}

main.o: main.c myqueue.h
	${CC} ${CFLAGS} -o main.o -c main.c

clean:
	rm -f main.o rtpproxy
