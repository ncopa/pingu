#ifndef PINGU_NETLINK_H
#define PINGU_NETLINK_H

int netlink_route_get(struct sockaddr *dst, u_int16_t *mtu, char *ifname);

#endif
