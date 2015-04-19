#include <linux/if_packet.h>
#include <linux/if_ether.h>

int ifindex_from_ifname(int sock, char* ifname);

int run_hook_script(char* hook_script_path, ...);

int broadcast_layer2(int sock, void* buffer, size_t len, uint16_t src_port, uint16_t dest_port, struct sockaddr_ll* dest_addr);

int open_socket_layer2(char* ifname, struct sockaddr_ll* bind_addr);

int open_socket(char* ifname, struct sockaddr_in* bind_addr, unsigned short listen_port);
