#ifndef PINGU_IFACE_H
#define PINGU_IFACE_H

#include <netinet/in.h>
#include <ev.h>

#include "sockaddr_util.h"
#include "list.h"

struct pingu_gateway {
	union sockaddr_any gw;
	int metric;
	struct list_head gateway_list_entry;
};

struct pingu_iface {
	char name[32];
	int index;
	int has_binding;
	int has_link;
	int fd;
	union sockaddr_any primary_addr;
	int route_table;
	struct list_head iface_list_entry;
	struct list_head ping_list;
	struct list_head gateway_list;
	struct ev_io socket_watcher;
};

struct pingu_iface *pingu_iface_get_by_name(const char *name);
struct pingu_iface *pingu_iface_get_by_index(int index);
int pingu_iface_bind_socket(struct pingu_iface *iface, int log_error);
int pingu_iface_usable(struct pingu_iface *iface);
int pingu_iface_init(struct ev_loop *loop, struct list_head *host_list);

void pingu_iface_set_addr(struct pingu_iface *iface, int family,
			  void *data, int len);

void pingu_iface_gateway(struct pingu_iface *iface, int family,
			 void *gateway_ptr, int metric, int action);
#endif
