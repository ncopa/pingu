#ifndef PINGU_HOST_H
#define PINGU_HOST_H

#include <ev.h>

#include "pingu_burst.h"

struct pingu_host {
	struct list_head host_list_entry;
	char *host;
	char *source_ip;
	char *label;
	char *interface;
	char *gateway;
	char *up_action;
	char *down_action;
	int status;
	int max_retries;
	int required_replies;
	ev_tstamp timeout;

	ev_tstamp burst_interval;
	struct ev_timer burst_timeout_watcher;
	struct pingu_burst burst;
	struct pingu_iface *iface;
};

void pingu_host_set_status(struct pingu_host *host, int status);
int pingu_host_init(struct ev_loop *loop, struct list_head *host_list);
int pingu_host_verify_status(struct ev_loop *loop, struct pingu_host *host);

#endif
