
#include <stdlib.h>
#include <unistd.h>
#include <ev.h>

#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_ping.h"

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

void pingu_host_set_status(struct pingu_host *host, int status)
{
	const char *action;
	host->burst.active = 0;
	if (host->status == status) {
		log_debug("%s: status is still %i", host->host, status);
		return;
	}
	host->status = status;
	log_info("%s: new status: %i", host->host, status);
	switch (host->status) {
	case 0:
		action = host->down_action;
		break;
	case 1:
		action = host->up_action;
		break;
	}
	if (action != NULL)
		execute_action(action);
}

int pingu_host_verify_status(struct ev_loop *loop, struct pingu_host *host)
{
	if (host->burst.pings_replied >= host->required_replies) {
		pingu_host_set_status(host, 1);
	} else if (host->burst.pings_sent >= host->max_retries) {
		pingu_host_set_status(host, 0);
	} else
		pingu_ping_send(loop, host);
	return 0;
}

int pingu_host_init(struct ev_loop *loop, struct list_head *host_list)
{
	struct pingu_host *host;
	list_for_each_entry(host, host_list, host_list_entry) {
		ev_timer_init(&host->burst_timeout_watcher,
			      pingu_burst_timeout_cb, 0, host->burst_interval);
		ev_timer_start(loop, &host->burst_timeout_watcher);
	}
	return 0;
}

