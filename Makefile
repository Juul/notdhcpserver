

all: server client

server: server.c phyconnect.c common.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpserver server.c phyconnect.c common.c crc32.c

client: client.c phyconnect.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpclient client.c phyconnect.c common.c crc32.c

clean:
	rm -f notdhcpserver notdhcpclient test

test: test.c
	$(CC) -o test test.c
