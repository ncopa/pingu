#ifndef PINGU_PING_H
#define PINGU_PING_H

#include <ev.h>

#include "list.h"
#include "pingu_host.h"

struct pingu_ping {
	int seq;
	struct pingu_host *host;
	struct list_head ping_list_entry;
	struct ev_timer timeout_watcher;
};

int pingu_ping_send(struct ev_loop *loop, struct pingu_host *host);
void pingu_ping_read_reply(struct ev_loop *loop, struct pingu_iface *iface);

#endif
