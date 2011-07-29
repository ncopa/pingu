#ifndef PINGU_NETLINK_H
#define PINGU_NETLINK_H

#include <ev.h>
#include "pingu_iface.h"

int kernel_init(struct ev_loop *loop);
int kernel_route_modify(int action, struct pingu_gateway *route,
			struct pingu_iface *iface, int table);			
#endif
