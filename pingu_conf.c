
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pingu_iface.h"
#include "pingu_host.h"
#include "xlib.h"

struct pingu_conf {
	const char *filename;
	FILE *fh;
	int lineno;
};

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

	/* strip comments and trailing \n */
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

static struct pingu_conf *pingu_conf_open(const char *filename)
{
	struct pingu_conf *f = calloc(1, sizeof(struct pingu_conf));
	if (f == NULL) {
		log_perror("calloc");
		return NULL;
	}
	f->fh = fopen(filename, "r");
	if (f->fh == NULL) {
		log_perror(filename);
		free(f);
		return NULL;
	}
	f->filename = filename;
	return f;
}

static void pingu_conf_close(struct pingu_conf *f)
{
	fclose(f->fh);
	free(f);
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

static char *pingu_conf_read_key_value(struct pingu_conf *conf, char **key,
				       char **value)
{
	static char line[1024];
	char *k = NULL, *v = NULL;
	while (k == NULL || *k == '\0') {
		if (fgets(line, sizeof(line), conf->fh) == NULL)
			return NULL;
		conf->lineno++;
		parse_line(line, &k, &v);
	}
	*key = k;
	*value = v;
	return line;
}

static int pingu_conf_read_iface(struct pingu_conf *conf, char *ifname)
{
	struct pingu_iface *iface;
	char *key, *value;

	iface = pingu_iface_get_by_name(value);
	if (iface != NULL) {
		log_error("Interface %s already declared (line %i)", conf->lineno);
		return -1;
	}

	iface = pingu_iface_get_by_name_or_new(ifname);
	if (iface == NULL)
		return -1;

	while (pingu_conf_read_key_value(conf, &key, &value)) {
		if (key == NULL || key[0] == '}')
			break;
		if (strcmp(key, "route-table") == 0) {
			pingu_iface_set_route_table(iface, atoi(value));
		} else if (strcmp(key, "load-balance") == 0) {
			int weight = 0;
			if (value != NULL) {
				weight = atoi(value);
				if (weight <= 0 || weight > 256) {
					log_error("Invalid load-balance weight %i on line %i",
						  weight, conf->lineno);
					return -1;
				}
			}
			pingu_iface_set_balance(iface, weight);
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  conf->lineno);
		}
	}
	return 0;
}

static int pingu_conf_read_host(struct pingu_conf *conf, char *hoststr)
{
	char *key, *value;
	struct pingu_host *host;

	host = pingu_host_new(xstrdup(hoststr), default_burst_interval,
			      default_max_retries, default_required_replies,
			      default_timeout, default_up_action,
			      default_down_action);
	while (pingu_conf_read_key_value(conf, &key, &value)) {
		if (key == NULL || key[0] == '}')
			break;
		if (strcmp(key, "bind-interface") == 0) {
			host->iface = pingu_iface_get_by_name_or_new(value);
			if (host->iface == NULL) {
				log_error("Undefined interface %s on line %i",
					   value, conf->lineno);
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
				  conf->lineno);
		}
	}
	if (host->iface == NULL)
		host->iface = pingu_iface_get_by_name_or_new(NULL);
	return 0;
}

int pingu_conf_parse(const char *filename)
{
	int r = 0;
	char *key, *value;
	struct pingu_conf *conf = pingu_conf_open(filename);

	if (conf == NULL)
		return -1;

	while (pingu_conf_read_key_value(conf, &key, &value)) {
		if (strcmp(key, "interface") == 0) {
			r = pingu_conf_read_iface(conf, chomp_bracket(value));
			if (r < 0)
				break;
		} else if (strcmp(key, "host") == 0) {
			r = pingu_conf_read_host(conf, chomp_bracket(value));
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
				  conf->lineno);
			r = -1;
			break;
		}
	}
	pingu_conf_close(conf);
	return r;
}
