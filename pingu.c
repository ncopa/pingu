
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pingu.h"
#include "xlib.h"

int pingu_verbose = 0;

struct provider {
	char *router;
	char *name;
	char *interface;
	char *up_action;
	char *down_action;
	int status;
	SLIST_ENTRY(provider) provider_list;
};

SLIST_HEAD(provider_list, provider);

#if 0
int skip(char **str, int whitespace)
{
	char *
	while (isspace(*p)) {
		if (*p == '\0')
			return;
		p++;
	}
}
#endif

/* note: this overwrite the line buffer */
void parse_line(char *line, char **key, char **value)
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

int read_config(const char *file, struct provider_list *head)
{
	FILE *f = fopen(file, "r");
	struct provider *p = NULL;
	int i = 0, lineno = 0;
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
//		printf("DEBUG: lineno=%i, key='%s', val='%s'\n", 
//				lineno, key, value);

		if (strcmp(key, "router") == 0) {
			p = xmalloc(sizeof(struct provider));
			memset(p, 0, sizeof(struct provider));
			p->router = xstrdup(value);
			p->status = 1; /* online by default */
			SLIST_INSERT_HEAD(head, p, provider_list);
		} else if (p && strcmp(key, "interface") == 0) {
			p->interface = xstrdup(value);
		} else if (p && strcmp(key, "provider") == 0) {
			p->name = xstrdup(value);
		} else if (p && strcmp(key, "up-action") == 0) {
			p->up_action = xstrdup(value);
		} else if (p && strcmp(key, "down-action") == 0) {
			p->down_action = xstrdup(value);
		} else if (p) {
			log_error("Unknown keyword '%s' on line %i", key, lineno);
		} else {
			log_error("provider not specified");
		}
	}
	return 0;
}

static int ping(const char *host)
{
	char cmd[280];
	snprintf(cmd, sizeof(cmd), "ping -c 1 -q %s >/dev/null 2>&1", host);
	return system(cmd);
}

void usage(int retcode)
{
	fprintf(stderr, "usage:\n");
	exit(retcode);
}

void dump_provider(struct provider *p)
{		
	printf("router:      %s\n"
	       "provider:    %s\n"
	       "interface:   %s\n"
	       "up-action:   %s\n"
	       "down-action: %s\n"
	       "p->status:   %i\n"
	       "\n",
	       p->router, p->name, p->interface,
	       p->up_action, p->down_action, p->status);
}

void ping_loop(struct provider_list *head, int interval)
{
	struct provider *p;
	while (1) {
		SLIST_FOREACH(p, head, provider_list) {
			int status = (ping(p->router) != 0);
			if (status != p->status) {
				p->status = status;
				printf("status changed for %s to %i\n",
					p->router, status);
			}
		}
		sleep(interval);
	}
}

int main(int argc, char *argv[])
{
	int c;
	char *config = "/etc/pingu.conf";
	char **hosts;
	int *offline;
	int hosts_count;
	int interval = 30;
	const char *script = NULL;
	struct provider_list providers;

	while ((c = getopt(argc, argv, "c:i:s:")) != -1) {
		switch (c) {
		case 'c':
			config = optarg;
			break;
		case 's':
			script = optarg;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	SLIST_INIT(&providers);
	if (read_config(config, &providers) == -1)
		return 1;

//	if (argc == 0)
//		usage(EXIT_FAILURE);

	offline = xmalloc(sizeof(int) * argc);
	memset(offline, 0, sizeof(int) * argc);

	ping_loop(&providers, interval);

	free(hosts);
	return 0;
}
