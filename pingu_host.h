#ifndef PINGU_HOST_H
#define PINGU_HOST_H

#include <ev.h>

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
	float timeout;

	ev_tstamp burst_interval;
	struct ev_timer burst_timeout_watcher;
};

#endif
