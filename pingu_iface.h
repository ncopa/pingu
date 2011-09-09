#ifndef PINGU_IFACE_H
#define PINGU_IFACE_H

#include <netinet/in.h>
#include <ev.h>

#include "pingu_gateway.h"
#include "sockaddr_util.h"
#include "list.h"

#define PINGU_ROUTE_TABLE_AUTO -1

struct pingu_iface {
	char name[32];
	int index;
	int has_link;
	int has_address;
	int has_binding;
	int has_route_rule;
	int has_multipath;
	int balance;
	int balance_weight;
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
struct pingu_iface *pingu_iface_get_by_name_or_new(const char *name);
int pingu_iface_bind_socket(struct pingu_iface *iface, int log_error);
int pingu_iface_usable(struct pingu_iface *iface);
int pingu_iface_init(struct ev_loop *loop);

void pingu_iface_set_addr(struct pingu_iface *iface, int family,
			  void *data, int len);
int pingu_iface_set_route_table(struct pingu_iface *iface, int table);

void pingu_iface_gw_action(struct pingu_iface *iface,
			   struct pingu_gateway *gw, int action);
void pingu_iface_update_routes(struct pingu_iface *iface, int action);
void pingu_iface_cleanup(void);

#endif
