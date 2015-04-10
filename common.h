#include <linux/if_packet.h>
#include <linux/if_ether.h>

int ifindex_from_ifname(int sock, char* ifname);

int run_hook_script(char* hook_script_path, ...);

int raw_udp_broadcast(int sock, void* buffer, size_t len, uint16_t src_port, uint16_t dest_port, struct sockaddr_ll* dest_addr);
