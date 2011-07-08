
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "icmp.h"
#include "pingu.h"
#include "xlib.h"
#include "log.h"
#include "list.h"

#include "pingu_host.h"

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "/etc/pingu/pingu.conf"
#endif

#ifndef DEFAULT_PIDFILE
#define DEFAULT_PIDFILE "/var/run/pingu.pid"
#endif

int pingu_verbose = 0, pid_file_fd = 0, pingu_daemonize = 0;
char *pid_file = DEFAULT_PIDFILE;
float default_burst_interval = 30.0;
float default_timeout = 1.0;
int default_max_retries = 5;
int default_required_replies = 2;
char *default_up_action = NULL;
char *default_down_action = NULL;
char *default_route_script = NULL;

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

int read_config(const char *file, struct list_head *head)
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
			list_add(&p->host_list_entry, head);
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
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
		}
	}
	return 0;
}

static void print_version(const char *program)
{
	printf("%s " PINGU_VERSION "\n", program);
}

int usage(const char *program)
{
	print_version(program);
	fprintf(stderr, "usage: %s [-dh] [-c CONFIG] [-p PIDFILE]\n"
		"options:\n"
       		" -c  Read configuration from FILE (default is " 
			DEFAULT_CONFIG ")\n"
		" -d  Fork to background (damonize)\n"
		" -h  Show this help\n"
		" -p  Use PIDFILE as pidfile (default is " 
			DEFAULT_PIDFILE ")\n"
		" -V  Print version and exit\n"
		"\n",
		program);
	return 1;
}

char *get_provider_gateway(struct pingu_host *p)
{
	if (p->gateway != NULL)
		return p->gateway;
	return p->host;
}

void exec_route_change(struct list_head *head)
{
	struct pingu_host *p;
	struct list_head *n;
	char **args;
	int i = 0, status;
	pid_t pid;

	if (default_route_script == NULL)
		return;
	
	list_for_each(n, head)
		i++;

	args = xmalloc(sizeof(char *) * (i + 2));

	i = 0;
	args[i++] = default_route_script;
	list_for_each_entry(p, head, host_list_entry) {
		if (p->status)
			args[i++] = get_provider_gateway(p);
	}
	args[i] = NULL;
	pid = fork();
	switch (pid) {
	case -1:
		log_perror("fork");
		goto free_and_return;
		break;
	case 0:
		execvp(default_route_script, args);
		log_perror(args[0]);
		exit(1);
	default:
		wait(&status);
	}

free_and_return:
	free(args);
	return;
}

static void remove_pid_file(void)
{
	if (pid_file_fd != 0) {
		close(pid_file_fd);
		pid_file_fd = 0;
		remove(pid_file);
	}
}

static int daemonize(void)
{
	char tmp[16];
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);

	if (setsid() < 0)
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);

	if (chdir("/") < 0)
		return -1;

	pid_file_fd = open(pid_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (pid_file_fd < 0) {
		log_error("Unable to open %s: %s.", pid_file, strerror(errno));
		return -1;
	}

	if (flock(pid_file_fd, LOCK_EX | LOCK_NB) < 0) {
		log_error("Unable to lock pid file (already running?).");
		close(pid_file_fd);
		pid_file_fd = 0;
		return -1;
	}

	ftruncate(pid_file_fd, 0);
	write(pid_file_fd, tmp, sprintf(tmp, "%d\n", getpid()));
	atexit(remove_pid_file);

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	umask(0);

	return 0;
}

int main(int argc, char *argv[])
{
	int c;
	struct list_head hostlist = LIST_INITIALIZER(hostlist);
	char *config_file = DEFAULT_CONFIG;
	int verbose = 0;
	static struct ev_loop *loop;

	while ((c = getopt(argc, argv, "c:dhp:Vv")) != -1) {
		switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			pingu_daemonize++;
			break;
		case 'h':
			return usage(basename(argv[0]));
		case 'p':
			pid_file = optarg;
			break;
		case 'V':
			print_version(basename(argv[0]));
			return 0;
		case 'v':
			verbose++;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	log_init(verbose);
	if (read_config(config_file, &hostlist) == -1)
		return 1;

	loop = ev_default_loop(0);
	pingu_iface_init(loop, &hostlist);
	pingu_host_init(loop, &hostlist);

	if (pingu_daemonize) {
		if (daemonize() == -1)
			return 1;
	}

	ev_run(loop, 0);
	return 0;
}
