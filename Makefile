
LIBS=-lnl -lnl-gen

all: server client

not: server_not_openwrt client_not_openwrt

server: server.c phyconnect.c common.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpserver server.c phyconnect.c common.c crc32.c swlib/swlib.c $(LIBS)

server_not_openwrt: server.c phyconnect.c common.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpserver server.c phyconnect.c common.c crc32.c

client: client.c phyconnect.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpclient client.c phyconnect.c common.c crc32.c swlib/swlib.c $(LIBS)

client_not_openwrt: client.c phyconnect.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpclient client.c phyconnect.c common.c crc32.c

clean:
	rm -f notdhcpserver notdhcpclient test

test: test.c
	$(CC) -o test test.c
