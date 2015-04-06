

all: server client

server: server.c phyconnect.c crc32.c phyconnect.h protocol.h crc32.h
	gcc -o notdhcpserver server.c phyconnect.c crc32.c

client: client.c phyconnect.c crc32.c phyconnect.h protocol.h crc32.h
	gcc -o notdhcpclient client.c phyconnect.c crc32.c

clean:
	rm -f notdhcpserver notdhcpclient
