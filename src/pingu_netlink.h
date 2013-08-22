#ifndef PINGU_NETLINK_H
#define PINGU_NETLINK_H

#include <ev.h>
#include "pingu_iface.h"

int kernel_init(struct ev_loop *loop);
int kernel_route_modify(int action, struct pingu_route *route,
			int table);
void route_changed_for_iface(struct pingu_iface *iface,
			     struct pingu_route *route, int action);
int kernel_route_multipath(int action, struct list_head *iface_list,
			   int table);
void kernel_cleanup_iface_routes(struct pingu_iface *iface);
void kernel_close(void);

#endif
