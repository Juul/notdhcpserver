
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int netlink_open_socket();
int netlink_handle_incoming(int nlsock, void (*callback)(char*, int));
int netlink_send_request(int nlsock);

struct nl_req {
  struct nlmsghdr hdr;
  struct rtgenmsg gen;
};
