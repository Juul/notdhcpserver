

all: server client

server: server.c
	gcc -o notdhcpserver server.c phyconnect.c

client: client.c phyconnect.c
	gcc -o notdhcpclient client.c phyconnect.c

clean:
	rm -f notdhcpserver notdhcpclient
