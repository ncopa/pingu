#ifndef PINGU_HOST_H
#define PINGU_HOST_H

#include <ev.h>

#include "pingu_burst.h"

#define PINGU_HOST_STATUS_OFFLINE 0
#define PINGU_HOST_STATUS_ONLINE 1

/* consider online by default */
#define PINGU_HOST_DEFAULT_STATUS  PINGU_HOST_STATUS_ONLINE

struct pingu_host {
	struct list_head host_list_entry;
	char *host;
	char *label;
	const char *up_action;
	const char *down_action;
	int status;
	int max_retries;
	int required_replies;
	ev_tstamp timeout;

	ev_tstamp burst_interval;
	struct ev_timer burst_timeout_watcher;
	struct pingu_burst burst;
	struct pingu_iface *iface;
};

void execute_action(const char *action);

struct pingu_host *pingu_host_new(char *hoststr, float burst_interval,
				  int max_retries, int required_replies,
				  float timeout, 
				  const char *up_action,
				  const char *down_action);
int pingu_host_set_status(struct pingu_host *host, int status);
int pingu_host_init(struct ev_loop *loop);
int pingu_host_verify_status(struct ev_loop *loop, struct pingu_host *host);
void pingu_host_dump_status(int fd, char *filter);
void pingu_host_cleanup(void);

#endif
