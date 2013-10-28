#ifndef PINGU_NETLINK_H
#define PINGU_NETLINK_H

#include <sys/types.h>

int netlink_route_get(struct sockaddr *dst, u_int16_t *mtu, char *ifname);

#endif
