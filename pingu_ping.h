#ifndef PINGU_PING_H
#define PINGU_PING_H

#include <ev.h>

#include "list.h"
#include "pingu_host.h"

#define PINGU_PING_IGNORE_ERROR 0
#define PINGU_PING_SET_STATUS_ON_ERROR 1

struct pingu_ping {
	int seq;
	struct pingu_host *host;
	struct list_head ping_list_entry;
	struct ev_timer timeout_watcher;
};

int pingu_ping_send(struct ev_loop *loop, struct pingu_host *host,
		    int set_status_on_failure);
void pingu_ping_read_reply(struct ev_loop *loop, struct pingu_iface *iface);

#endif
