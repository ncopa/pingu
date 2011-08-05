
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pingu_iface.h"
#include "pingu_host.h"
#include "xlib.h"

static float default_burst_interval = 30.0;
static float default_timeout = 1.0;
static int default_max_retries = 5;
static int default_required_replies = 3;
static char *default_up_action = NULL;
static char *default_down_action = NULL;

/* note: this overwrite the line buffer */
static void parse_line(char *line, char **key, char **value)
{
	char *p;

	(*value) = NULL;
	(*key) = NULL;

	/* strip comments and trailng \n */
	p = strpbrk(line, "#\n");
	if (p)
		*p = '\0';

	/* skip leading whitespace */
	while (isspace(*line))
		line++;
	if (*line == '\0')
		return;
		
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
	while (isspace(*p))
		p++;
	if (*p == '\0')
		return;

	(*value) = p;
}

static FILE *pingu_conf_open(const char *filename)
{
	FILE *f = fopen(filename, "r");
	if (f == NULL)
		log_perror(filename);
	return f;
}

static char *chomp_bracket(char *str)
{
	char *p = str;
	/* chomp */
	while (!isspace(*p))
		p++;
	*p = '\0';
	return str;
}

static char *pingu_conf_get_key_value(FILE *f, char **key, char **value, int *lineno)
{
	static char line[1024];
	char *k = NULL, *v = NULL;
	while (k == NULL || *k == '\0') {
		if (fgets(line, sizeof(line), f) == NULL)
			return NULL;
		(*lineno)++;
		parse_line(line, &k, &v);
	}
	*key = k;
	*value = v;
	return line;
}
	
		

static int pingu_conf_read_iface(FILE *f, char *ifname, int *lineno)
{
	struct pingu_iface *iface;
	char *key, *value;
	
	iface = pingu_iface_get_by_name(value);
	if (iface != NULL) {
		log_error("Interface %s already declared");
		return -1;
	}

	iface = pingu_iface_get_by_name_or_new(ifname);
	if (iface == NULL)
		return -1;

	while (pingu_conf_get_key_value(f, &key, &value, lineno)) {
		if (key == NULL || key[0] == '}')
			break;
		if (strcmp(key, "route-table") == 0) {
			pingu_iface_set_route_table(iface, atoi(value));
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
		}
	}
	return 0;
}

static int pingu_conf_read_host(FILE *f, char *hoststr, int *lineno)
{
	char *key, *value;
	struct pingu_host *host;
	
	host = pingu_host_new(xstrdup(hoststr), default_burst_interval,
			      default_max_retries, default_required_replies,
			      default_timeout, default_up_action,
			      default_down_action);
	while (pingu_conf_get_key_value(f, &key, &value, lineno)) {
		if (key == NULL || key[0] == '}')
			break;
		if (strcmp(key, "bind-interface") == 0) {
			host->iface = pingu_iface_get_by_name_or_new(value);
			if (host->iface == NULL) {
				log_error("Undefined interface %s on line %i",
					   value, lineno);
				return -1;
			}
		} else if (strcmp(key, "label") == 0) {
			host->label = xstrdup(value);
		} else if (strcmp(key, "up-action") == 0) {
			host->up_action = xstrdup(value);
		} else if (strcmp(key, "down-action") == 0) {
			host->down_action = xstrdup(value);
		} else if (strcmp(key, "retry") == 0) {
			host->max_retries = atoi(value);
		} else if (strcmp(key, "required") == 0) {
			host->required_replies = atoi(value);
		} else if (strcmp(key, "timeout") == 0) {
			host->timeout = atof(value);
		} else if (strcmp(key, "interval") == 0) {
			host->burst_interval = atof(value);
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
		}
	}
	if (host->iface == NULL)
		host->iface = pingu_iface_get_by_name_or_new(NULL);
	return 0;
}

int pingu_conf_read(const char *filename)
{
	int lineno = 0;
	char line[256];
	int r = 0;
	FILE *f = pingu_conf_open(filename);
	
	if (f == NULL)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *key, *value;
		lineno++;
		parse_line(line, &key, &value);
		if (key == NULL)
			continue;
		if (strcmp(key, "interface") == 0) {
			r = pingu_conf_read_iface(f, chomp_bracket(value), &lineno);
			if (r < 0)
				break;
		} else if (strcmp(key, "host") == 0) {
			r = pingu_conf_read_host(f, chomp_bracket(value), &lineno);
			if (r < 0)
				break;
		} else if (strcmp(key, "interval") == 0) {
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
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
			r = -1;
			break;
		}
	}
	return r;
}
