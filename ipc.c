#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "server.h"
#include "ipc.h"

char* socket_file = "/tmp/notdhcpserver.sock";

extern struct interface* interfaces;
extern int has_switch;

struct uclient* uclients = NULL;
int uclient_count = 0;

int usock;

struct uclient* add_uclient(int fd) {

  struct uclient *cur;

  struct uclient *ucl = malloc(sizeof(struct uclient));
  if(!ucl) {
    return NULL;
  }
  
  ucl->fd = fd;
  ucl->next = NULL;
  ucl->msg = malloc(MAX_UCLIENT_MSG_SIZE+1);
  if(!(ucl->msg)) {
    return NULL;
  }

  ucl->msg_len = 0;  

  if(!uclients) {
    uclients = ucl;
    uclient_count++;
    return ucl;
  }
  
  cur = uclients;
  while(cur->next) {
    cur = cur->next;
  }

  cur->next = ucl;
  uclient_count++;
  return ucl;
}

int remove_uclient(struct uclient* ucl) {

  struct uclient *cur;
  struct uclient *prev = NULL;

  if(!ucl || !uclients)
    return -1;
  
  if(uclients == ucl) {
    uclients = ucl->next;
    close(ucl->fd);
    free(ucl->msg);
    free(ucl);
    uclient_count--;
    return 0;
  }

  for(cur = uclients; cur->next; cur = cur->next) {
    if(cur == ucl) {
      prev->next = cur->next;
      close(ucl->fd);
      free(ucl->msg);
      free(ucl);
      uclient_count--;
      return 0;
    }
    prev = cur;
  }
  return -1;
}

// check if fd is a uclient fd
// and return its uclient struct
struct uclient* is_uclient_fd(int fd) {

  struct uclient *cur;

  if(!uclients)
    return NULL;
  
  for(cur = uclients; cur->next; cur = cur->next) {
    if(cur->fd == fd) {
      return cur;
    }
  }
  return NULL;
}

void send_link_status(struct uclient* ucl) {
  struct interface* iface;
  char* buf;
  size_t len = 0;
  FILE *stream;

  stream = open_memstream(&buf, &len);

  fprintf(stream, "{\n");

#ifdef SWLIB
  if(has_switch > 0) {
    fprintf(stream, "  \"has_switch\": true,\n");
  } else {
    fprintf(stream, "  \"has_switch\": false,\n");
  }
#else
  fprintf(stream, "  \"has_switch\": false,\n");
#endif

  fprintf(stream, "  \"interfaces\": [\n");

  iface = interfaces;
  do {
    fprintf(stream, "    {\n");
    fprintf(stream, "      \"ifname\": \"%s\",\n", iface->ifname);
    fprintf(stream, "      \"vlan\": %d,\n", iface->vlan);
    fprintf(stream, "      \"ip\": \"%s\",\n", iface->ip);
    fprintf(stream, "      \"netmask\": %d,\n", iface->netmask);
    fprintf(stream, "      \"time_since_last_contact\": %lld,\n", (long long) iface->time_passed);
    if(iface->state == STATE_STOPPED) {
      fprintf(stream, "      \"state\": \"unplugged\"\n");
    } else if(iface->state == STATE_LISTENING) {
      fprintf(stream, "      \"state\": \"plugged\"\n");
    } else if(iface->state == STATE_GOT_ACK) {
      fprintf(stream, "      \"state\": \"connected\"\n");
    } else {
      fprintf(stream, "      \"state\": \"unknown\"\n");
    }
    if(iface->next) {
      fprintf(stream, "    },\n");
    } else {
      fprintf(stream, "    }\n");
    }
  } while(iface = iface->next);

  fprintf(stream, "  ]\n");
  fprintf(stream, "}\n");

  fflush(stream);
  fclose(stream);

  if(len <= 0) {
    return;
  }

  send_uclient_response(ucl, buf, len+1);
}

void handle_uclient_msg(struct uclient* ucl) {

  char cmd;
  char* arg;

  cmd = (ucl->msg)[0];
  arg = (ucl->msg)+1;

  switch(cmd) {

  case 'i':
    send_link_status(ucl);
    break;
  }

  remove_uclient(ucl);
}

void send_uclient_response(struct uclient* ucl, char* data, size_t len) {
  int sent_data = 0;
  ssize_t ret;

  while(sent_data < len) {
    ret = send(ucl->fd, data + sent_data, len - sent_data, 0);
    if(ret < 0) {
      return;
    }
    sent_data += ret;
  }

  close(ucl->fd);
}

void receive_uclient_msg(struct uclient* ucl) {
  int num_bytes = read(ucl->fd, ucl->msg + ucl->msg_len, MAX_UCLIENT_MSG_SIZE - ucl->msg_len);

  if(num_bytes < 0) {
    fprintf(stderr, "Error reading from socket %s: %s\n", socket_file, strerror(errno));
    return;
  }

  // TODO better check that entire message has been received
  if(num_bytes >= 1) {
    handle_uclient_msg(ucl);
  }
  
//  ucl->msg_len += num_bytes;
}



// if get_response > 1 then response is received and printed
int send_uclient_msg(char cmd, char* arg, int get_response) {

  int sock;
  size_t cmd_len;
  int bytes_written;
  int bytes_received;
  int ret;
  char* full_cmd;
  struct sockaddr_un addr;
  char received[MAX_UCLIENT_RESPONSE_SIZE + 1];
	
  if(arg) {
    cmd_len = strlen(arg) + 2; // one for leading cmd and one for trailing \0
    if(cmd_len > MAX_UCLIENT_MSG_SIZE) {
      fprintf(stderr, "Command too long (max %d bytes)\n", MAX_UCLIENT_MSG_SIZE);
      return -1;
    }
  } else {
    cmd_len = 2;
  }

  full_cmd = malloc(cmd_len);
  if(!full_cmd) {
    return -1;
  }

  if(arg) {
    snprintf(full_cmd, cmd_len, "%c%s", cmd, arg);
  } else {
    snprintf(full_cmd, cmd_len, "%c", cmd);
  }

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, socket_file);

  sock = socket(AF_LOCAL, SOCK_STREAM, 0);
			
  if(connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    fprintf(stderr, "Connect failed to %s: %s\n", socket_file, strerror(errno));
    fprintf(stderr, "Are you sure you have a running notdhcpserver instance?\n");
    free(full_cmd);
    close(sock);
    return -1;
  }

  bytes_written = 0;
			
  while(bytes_written < cmd_len) {
    ret = write(sock, full_cmd+bytes_written, cmd_len-bytes_written);
    if(ret < 0)  {
      fprintf(stderr, "Write failed to %s: %s\n", socket_file, strerror(errno));
      free(full_cmd);
      close(sock);
      return -1;
    }
    bytes_written += ret;
  }

  free(full_cmd);

  if(get_response) {
    bytes_received = 0;
    // receive until disconnect, then print received data
    while(1) {
      ret = read(sock, received + bytes_received, MAX_UCLIENT_RESPONSE_SIZE - bytes_received);

      if(ret < 0) {
        fprintf(stderr, "Error reading from socket %s: %s\n", socket_file, strerror(errno));
        return -1;
      } else if(ret == 0) {
        received[bytes_received] = '\0';
        break;
      }
      bytes_received += ret;
    }
    printf("%s", received);
  }

  close(sock);
  return 0;
}

int open_ipc_socket() {

  struct sockaddr_un addr;
  int usock_opts;
  int ret;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, socket_file);

  usock = socket(AF_LOCAL, SOCK_STREAM, 0);
			
  usock_opts = fcntl(usock, F_GETFL, 0);
  ret = fcntl(usock, F_SETFL, usock_opts | O_NONBLOCK);
  if(ret == -1) {
    return ret;
  }

  if(connect(usock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    if(errno != ENOENT) {
      close(usock);
      unlink(socket_file);
      usock = socket(AF_LOCAL, SOCK_STREAM, 0);
    }
    //    printf("connect() error: %d | %s\n", errno, strerror(errno));
  } else {
    fprintf(stderr, "Looks like notdhcpserver is already running.\nUse -l to get status.");
    return 1;
  }

  if(bind(usock, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
    fprintf(stderr, "Failed to bind socket %s: %s\n", socket_file, strerror(errno));
    return 1;
  }

  if(listen(usock, 10) < 0) {
    fprintf(stderr, "Listen failed on socket %s: %s\n", socket_file, strerror(errno));
    return 1;
  }

  return 0;
}


void accept_ipc_connection() {

	struct sockaddr addr;
	socklen_t addr_size = sizeof(struct sockaddr);
  int fd;

  if(uclient_count >= MAX_UCLIENTS) {
    fprintf(stderr, "Client connection limit reached (%d)\n", MAX_UCLIENTS);
    return;
  }

	fd = accept(usock, (struct sockaddr *)&addr, &addr_size);

	if(fd < 0) {
    fprintf(stderr, "Accept failed on socket %s: %s\n", socket_file, strerror(errno));
    return;
  }

  add_uclient(fd);

  return;
}

// returns the new maxfd
int add_uclients_to_fd_set(fd_set* readfds, int maxfd) {
  struct uclient* ucl;

  // add unix ipc socket to set
  FD_SET(usock, readfds);
  maxfd = MAX(maxfd, usock);

  FOR_ALL_UCLIENTS(ucl) {
    FD_SET(ucl->fd, readfds);
    maxfd = MAX(maxfd, ucl->fd);
  }
  return maxfd;
}

void handle_uclient_connections(fd_set* readfds) {
  struct uclient* ucl;

  if(FD_ISSET(usock, readfds)) {
    accept_ipc_connection();
  }

  FOR_ALL_UCLIENTS(ucl) {
    if(FD_ISSET(ucl->fd, readfds)) {
      receive_uclient_msg(ucl);
    }
  }
}
