#ifndef PINGU_IFACE_H
#define PINGU_IFACE_H

#include <ev.h>
#include "list.h"

struct pingu_iface {
	char name[32];
	int fd;
	struct list_head iface_list_entry;
//	struct list_head burst_list;
	struct list_head ping_list;
	struct ev_io socket_watcher;
};

struct pingu_iface *pingu_iface_find(const char *name);
struct pingu_iface *pingu_iface_find_or_create(struct ev_loop *loop, const char *name);
int pingu_iface_init(struct ev_loop *loop, struct list_head *host_list);

#endif
