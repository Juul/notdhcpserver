
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

unsigned short ComputeChecksum(unsigned char *data, int len)
{
    long sum = 0;  /* assume 32 bit long, 16 bit short */
    unsigned short *temp = (unsigned short *)data;

    while(len > 1){
        sum += *temp++;
        if(sum & 0x80000000)   /* if high order bit set, fold */
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if(len)       /* take care of left over byte */
        sum += (unsigned short) *((unsigned char *)temp);

    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

int raw_udp_broadcast(int sock, void* buffer, size_t len, uint16_t src_port, uint16_t dest_port) {
  struct sockaddr_in dest_addr;
  struct ip* ip_header;
  struct udphdr* udp_header;
  void* payload;
  size_t to_send;
  size_t sent = 0;
  size_t ret;

  void* data = (void*) malloc(sizeof(struct ip) + sizeof(struct udphdr) + len);
  if(!data) {
    return - 1;
  }

  ip_header = data;
  udp_header = data + sizeof(struct ip);

  payload = udp_header + sizeof(struct udphdr);
  memcpy(payload, buffer, len);
  to_send = sizeof(struct ip) + sizeof(struct udphdr) + len;

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
  dest_addr.sin_port = htons(dest_port);
  
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = IPTOS_LOWDELAY;
  ip_header->ip_id = 0;
  ip_header->ip_ttl = 16;
  ip_header->ip_p = IPPROTO_UDP;
  ip_header->ip_off = 0;
  inet_pton(AF_INET, "0.0.0.0", &(ip_header->ip_src));
  inet_pton(AF_INET, "255.255.255.255", &(ip_header->ip_dst));
  //  ip_header->ip_sum = 0;
  ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + len);
  ip_header->ip_sum = ComputeChecksum((unsigned char *)ip_header, ip_header->ip_hl*4);

  udp_header->source = htons(src_port);
  udp_header->dest = htons(dest_port);
  udp_header->check = htons(0);
  udp_header->len = htons(sizeof(struct udphdr) + len);
  
  while(sent < to_send) {
    ret = sendto(sock, data + sent, to_send - sent, 0, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr));
    if(ret <= 0) {
      free(data);
      return ret;
    }
    sent += ret;
  }

  free(data);
  return sent - sizeof(struct ip) - sizeof(struct udphdr);
}


int run_hook_script(char* hook_script_path, ...) {
  va_list args;
  char* cur;
  char* cmd;
  int len;
  int i;
  int ret;

  if(!hook_script_path) {
    return;
  }

  len = strlen(hook_script_path + 1);
  
  va_start(args, hook_script_path); 
  
  while((cur = va_arg(args, char *)) != NULL) {
    len += strlen(cur) + 2;
  }
  
  va_end(args);

  cmd = malloc(len);

  va_start(args, hook_script_path); 
  
  i = 0;
  strcpy(cmd, hook_script_path);
  i += strlen(hook_script_path);
  cmd[i++] = ' ';

  while((cur = va_arg(args, char *)) != NULL) {
    strcpy(cmd + i, cur);
    i += strlen(cur);
    cmd[i++] = ' ';
  }

  cmd[i-1] = '\0';
    
  va_end(args);

  ret = system(cmd);

  free(cmd);

  return ret;
}
