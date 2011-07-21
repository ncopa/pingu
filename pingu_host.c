
#include <ctype.h>
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
float default_burst_interval = 30.0;
float default_timeout = 1.0;
int default_max_retries = 5;
int default_required_replies = 2;
char *default_up_action = NULL;
char *default_down_action = NULL;
char *default_route_script = NULL;
int default_route_table = 10;

/* note: this overwrite the line buffer */
static void parse_line(char *line, char **key, char **value)
{
	char *p;

	/* strip comments and trailng \n */
	p = strpbrk(line, "#\n");
	if (p)
		*p = '\0';

	(*value) = NULL;
	if (line[0] == '\0') {
		(*key) = NULL;
		return;
	}
	
	/* skip leading whitespace */
	while (isspace(*p)) {
		if (*p == '\0')
			return;
		p++;
	}
	(*key) = line;

	/* find space between keyword and value */
	p = line;
	while (!isspace(*p)) {
		if (*p == '\0')
			return;
		p++;
	}
	*p++ = '\0';

	/* find value */
	while (isspace(*p)) {
		if (*p == '\0')
			return;
		p++;
	}
	(*value) = p;
}

int pingu_host_read_config(const char *file)
{
	FILE *f = fopen(file, "r");
	struct pingu_host *p = NULL;
	int lineno = 0;
	char line[256];
	if (f == NULL) {
		log_perror(file);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *key, *value;
		lineno++;
		parse_line(line, &key, &value);
		if (key == NULL)
			continue;

		if (strcmp(key, "host") == 0) {
			p = xmalloc(sizeof(struct pingu_host));
			memset(p, 0, sizeof(struct pingu_host));
			p->host = xstrdup(value);
			p->gateway = xstrdup(value);
			p->status = 1; /* online by default */
			p->max_retries = default_max_retries;
			p->timeout = default_timeout;
			p->up_action = default_up_action;
			p->down_action = default_down_action;
			p->required_replies = default_required_replies;
			p->burst_interval = default_burst_interval;
			list_add(&p->host_list_entry, &host_list);
			continue;
		}
		if (p == NULL) {
			if (strcmp(key, "interval") == 0) {
				default_burst_interval = atof(value);
			} else if (strcmp(key, "retry") == 0) {
				default_max_retries = atoi(value);
			} else if (strcmp(key, "required") == 0) {
				default_required_replies = atoi(value);
			} else if (strcmp(key, "timeout") == 0) {
				default_timeout = atof(value);
			} else if (strcmp(key, "up-action") == 0) {
				default_up_action = xstrdup(value);
			} else if (strcmp(key, "down-action") == 0) {
				default_down_action = xstrdup(value);
			} else if (strcmp(key, "route-script") == 0) {
				default_route_script = xstrdup(value);
			} else if (strcmp(key, "route-table") == 0) {
				default_route_table = atoi(value);
			} else 
				log_error("host not specified");
		} else if (strcmp(key, "interface") == 0) {
			p->interface = xstrdup(value);
		} else if (strcmp(key, "gateway") == 0) {
			if (p->gateway)
				free(p->gateway);
			p->gateway = xstrdup(value);
		} else if ((strcmp(key, "name") == 0) || (strcmp(key, "label") == 0)) {
			p->label = xstrdup(value);
		} else if (strcmp(key, "up-action") == 0) {
			p->up_action = xstrdup(value);
		} else if (strcmp(key, "down-action") == 0) {
			p->down_action = xstrdup(value);
		} else if (strcmp(key, "retry") == 0) {
			p->max_retries = atoi(value);
		} else if (strcmp(key, "required") == 0) {
			p->required_replies = atoi(value);
		} else if (strcmp(key, "timeout") == 0) {
			p->timeout = atof(value);
		} else if (strcmp(key, "source-ip") == 0) {
			p->source_ip = xstrdup(value);
		} else if (strcmp(key, "interval") == 0) {
			p->burst_interval = atof(value);
		} else if (strcmp(key, "route-table") == 0) {
			p->iface_route_table = atoi(value);
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
		}
	}
	return 0;
}

static char *get_provider_gateway(struct pingu_host *p)
{
	if (p->gateway != NULL)
		return p->gateway;
	return p->host;
}

static void exec_route_change(void)
{
	struct pingu_host *host;
	struct list_head *n;
	char **args;
	int i = 0;
	pid_t pid;

	if (default_route_script == NULL)
		return;
	
	list_for_each(n, &host_list)
		i++;

	args = malloc(sizeof(char *) * (i + 2));
	if (args == NULL) {
		log_perror("malloc");
		return;
	}

	i = 0;
	args[i++] = default_route_script;
	list_for_each_entry(host, &host_list, host_list_entry) {
		if (host->status)
			args[i++] = get_provider_gateway(host);
	}
	args[i] = NULL;
	pid = fork();
	if (pid < 0) {
		log_perror("fork");
		free(args);
		return;
	}
	if (pid == 0) {
		/* the child */
		execvp(default_route_script, args);
		log_perror(args[0]);
		exit(1);
	}
	/* libev reaps all children */
}

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
	host->burst.active = 0;
	if (host->status == status) {
		log_debug("%s: %s: status is still %i",
			host->iface->name, host->host, status);
		return status;
	}
	host->status = status;
	log_info("%s: %s: new status: %i",
		host->iface->name, host->host, status);
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
	exec_route_change();
	return status;
}

int pingu_host_verify_status(struct ev_loop *loop, struct pingu_host *host)
{
	if (host->burst.pings_replied >= host->required_replies) {
		pingu_host_set_status(host, 1);
	} else if (host->burst.pings_sent >= host->max_retries) {
		pingu_host_set_status(host, 0);
	} else
		pingu_ping_send(loop, host, 1);
	return 0;
}

int pingu_host_init(struct ev_loop *loop, const char *config)
{
	struct pingu_host *host;
	if (pingu_host_read_config(config) < 0)
		return -1;

	if (pingu_iface_init(loop, &host_list) < 0)
		return -1;
	
	list_for_each_entry(host, &host_list, host_list_entry) {
		ev_timer_init(&host->burst_timeout_watcher,
			      pingu_burst_timeout_cb, 0, host->burst_interval);
		ev_timer_start(loop, &host->burst_timeout_watcher);
	}
	return 0;
}

