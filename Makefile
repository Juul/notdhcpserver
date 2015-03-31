

all: notdhcpserver

notdhcpserver: main.c
	gcc -o notdhcpserver main.c

clean:
	rm -f notdhcpserver
