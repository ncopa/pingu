
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ev.h>

#include "list.h"
#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_iface.h"
#include "pingu_ping.h"
#include "xlib.h"

static struct list_head host_list = LIST_INITIALIZER(host_list);

static void execute_action(const char *action)
{
	pid_t pid;
	const char *shell = getenv("SHELL");
	if (shell == NULL)
		shell = "/bin/sh";

	log_debug("executing '%s'", action);
	pid = fork();
	if (pid < 0) {
		log_perror("fork");
		return;
	}
	if (pid == 0) {
		execl(shell, shell, "-c", action, NULL);
		log_perror(action);
		exit(1);
	}
}

int pingu_host_set_status(struct pingu_host *host, int status)
{
	const char *action;
	int route_action = 0;
	host->burst.active = 0;
	if (host->status == status) {
		log_debug("%s: status is still %i", host->label, status);
		return status;
	}
	host->status = status;
	log_info("%s: new status: %i", host->label, status);
	switch (host->status) {
	case 0:
		action = host->down_action;
		route_action = RTM_DELROUTE;
		break;
	case 1:
		action = host->up_action;
		route_action =  RTM_NEWROUTE;
		break;
	}
	if (action != NULL)
		execute_action(action);
	pingu_iface_update_routes(host->iface, route_action);
	return status;
}

int pingu_host_verify_status(struct ev_loop *loop, struct pingu_host *host)
{
	if (host->burst.pings_replied >= host->required_replies) {
		pingu_host_set_status(host, PINGU_HOST_STATUS_ONLINE);
	} else if (host->burst.pings_sent >= host->max_retries) {
		pingu_host_set_status(host, PINGU_HOST_STATUS_OFFLINE);
	} else
		pingu_ping_send(loop, host, PINGU_PING_SET_STATUS_ON_ERROR);
	return 0;
}

struct pingu_host *pingu_host_new(char *hoststr, float burst_interval,
				  int max_retries, int required_replies,
				  float timeout, 
				  const char *up_action,
				  const char *down_action)
{
	struct pingu_host *host = calloc(1, sizeof(struct pingu_host));
	
	if (host == NULL) {
		log_perror(hoststr);
		return NULL;
	}
	
	host->host = hoststr;
	host->status = PINGU_HOST_DEFAULT_STATUS;
	host->burst_interval = burst_interval;
	host->max_retries = max_retries;
	host->required_replies = required_replies;
	host->timeout = timeout;
	host->up_action = up_action;
	host->down_action = down_action;
	
	list_add(&host->host_list_entry, &host_list);
	return host;
}

struct pingu_host *pingu_host_find_by_iface(struct pingu_iface *iface)
{
	struct pingu_host *host;
	list_for_each_entry(host, &host_list, host_list_entry)
		if (host->iface == iface)
			return host;
	return NULL;
}

int pingu_host_init(struct ev_loop *loop)
{
	struct pingu_host *host;
	list_for_each_entry(host, &host_list, host_list_entry) {
		if (host->label == NULL)
			host->label = host->host;
		ev_timer_init(&host->burst_timeout_watcher,
			      pingu_burst_timeout_cb, 0, host->burst_interval);
		ev_timer_start(loop, &host->burst_timeout_watcher);
	}
	return 0;
}

