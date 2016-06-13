
LIBS=-lnl-3 -lnl-genl-3
INCLUDES=-I./swlib -I$(STAGING_DIR)/usr/include/libnl3

all: client server

not: server_not_openwrt client_not_openwrt


server: server.c phyconnect.c common.c crc32.c server.h phyconnect.h common.h protocol.h crc32.h ipc.h swlib/swlib.h switch.h
	$(CC) -DSWLIB -o notdhcpserver server.c phyconnect.c common.c crc32.c ipc.c swlib/swlib.c switch.c $(LIBS) $(INCLUDES) $(CFLAGS) $(LDFLAGS)

server_not_openwrt: server.c phyconnect.c common.c crc32.c server.h phyconnect.h common.h protocol.h crc32.h ipc.h
	$(CC) -o notdhcpserver server.c phyconnect.c common.c crc32.c ipc.c

client: client.c phyconnect.c crc32.c phyconnect.h common.h protocol.h crc32.h swlib/swlib.h switch.h
	echo $(INCLUDES)
	$(CC) -DSWLIB -o notdhcpclient client.c phyconnect.c common.c crc32.c swlib/swlib.c switch.c $(LIBS) $(INCLUDES) $(CFLAGS) $(LDFLAGS)

client_not_openwrt: client.c phyconnect.c crc32.c phyconnect.h common.h protocol.h crc32.h
	$(CC) -o notdhcpclient client.c phyconnect.c common.c crc32.c

clean:
	rm -f notdhcpserver notdhcpclient test

test: test.c
	$(CC) -o test test.c
