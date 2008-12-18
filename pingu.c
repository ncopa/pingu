
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
	char *name;
	char *interface;
	char *pinghost;
	char *up_action;
	char *down_action;
	int status;
};

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

struct provider **read_config(const char *file)
{
	FILE *f = fopen(file, "r");
	struct provider *p = NULL;
	struct provider **list = NULL;
	int i = 0, lineno = 0;
	char line[256];
	if (f == NULL) {
		log_perror(file);
		return NULL;
	}
	while (fgets(line, sizeof(line), f)) {
		char *key, *value;
		lineno++;
		parse_line(line, &key, &value);
		if (key == NULL)
			continue;
		printf("DEBUG: lineno=%i, key='%s', val='%s'\n", 
				lineno, key, value);

		if (strcmp(key, "interface") == 0) {
			list = xrealloc(list, (i + 2) * sizeof(struct provider *));
			p = xmalloc(sizeof(struct provider));
			p->name = xstrdup(value);
			list[i] = p;
			i++;
		} else if (p && strcmp(key, "provider") == 0) {
			p->name = xstrdup(value);
		} else if (p && strcmp(key, "pinghost") == 0) {
			p->pinghost = xstrdup(value);
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
	list[i] = NULL;
	return list;
}

static int ping(const char *host)
{
	char cmd[280];
	snprintf(cmd, sizeof(cmd), "ping -c 1 -q %s", host);
	return system(cmd);
}

void usage(int retcode)
{
	fprintf(stderr, "usage:\n");
	exit(retcode);
}

void ping_loop(char *hosts[], int offline[], int count, int interval)
{
	int i;
	while (1) {
		for (i = 0; i < count; i++) {
			int status = (ping(hosts[i]) != 0);
			if (status != offline[i]) {
				offline[i] = status;
				printf("status changed for %s to %i\n",
					hosts[i], status);
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
	struct provider **providers;

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

	providers = read_config(config);
	if (providers == NULL)
		return 1;

	if (argc == 0)
		usage(EXIT_FAILURE);

	offline = xmalloc(sizeof(int) * argc);
	memset(offline, 0, sizeof(int) * argc);

	ping_loop(argv, offline, argc, interval);

	free(hosts);
	return 0;
}
