CFLAGS=-Wall -g -O0
LDLIBS=-L/usr/local/lib -lcrypto

all: dhe_server dhe
dhe: dhe.o common.o
dhe_server: dhe_server.o common.o

start_client:
	./dhe

start_server:
	./dhe_server

clean:
	rm -f dhe dhe_server *.o

.PHONY: start_client start_server clean
