

all: server client

server: server.c phyconnect.c phyconnect.h protocol.h
	gcc -o notdhcpserver server.c phyconnect.c

client: client.c phyconnect.c phyconnect.h protocol.h
	gcc -o notdhcpclient client.c phyconnect.c

clean:
	rm -f notdhcpserver notdhcpclient
