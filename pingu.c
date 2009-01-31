
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "icmp.h"
#include "pingu.h"
#include "xlib.h"

#define DEFAULT_CONFIG "/etc/pingu.conf"
#define DEFAULT_PIDFILE "/var/run/pingu.pid"

int pingu_verbose = 0, pid_file_fd = 0, pingu_daemonize = 0;
char *pid_file = DEFAULT_PIDFILE;
int interval = 30;
float default_timeout = 1.0;
int default_retry = 3;
char *default_up_action = NULL;
char *default_down_action = NULL;

struct provider {
	struct sockaddr_in address;
	char *name;
	char *interface;
	char *up_action;
	char *down_action;
	int status;
	int retry;
	float timeout;
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

		if (strcmp(key, "host") == 0) {
			p = xmalloc(sizeof(struct provider));
			memset(p, 0, sizeof(struct provider));
			if (init_sockaddr(&p->address, value) < 0)
				return 1;
			p->status = 1; /* online by default */
			p->retry = default_retry;
			p->timeout = default_timeout;
			p->up_action = default_up_action;
			p->down_action = default_down_action;
			SLIST_INSERT_HEAD(head, p, provider_list);
			continue;
		}
		if (p == NULL) {
			if (strcmp(key, "interval") == 0) {
				interval = atoi(value);
			} else if (strcmp(key, "retry") == 0) {
				default_retry = atoi(value);
			} else if (strcmp(key, "timeout") == 0) {
				default_timeout = atof(value);
			} else if (strcmp(key, "up-action") == 0) {
				default_up_action = value;
			} else if (strcmp(key, "down-action") == 0) {
				default_down_action = value;
			} else 
				log_error("host not specified");
		} else if (strcmp(key, "interface") == 0) {
			p->interface = xstrdup(value);
		} else if (strcmp(key, "name") == 0) {
			p->name = xstrdup(value);
		} else if (strcmp(key, "up-action") == 0) {
			p->up_action = xstrdup(value);
		} else if (strcmp(key, "down-action") == 0) {
			p->down_action = xstrdup(value);
		} else if (strcmp(key, "retry") == 0) {
			p->retry = atoi(value);
		} else if (strcmp(key, "timeout") == 0) {
			p->timeout = atof(value);
		} else {
			log_error("Unknown keyword '%s' on line %i", key,
				  lineno);
		}
	}
	return 0;
}

int do_ping(struct sockaddr_in *to, int seq, int retries, float timeout)
{
	__u8 buf[1500];
	struct iphdr *ip = (struct iphdr *) buf;
	struct icmphdr *icp;
	struct sockaddr_in from;
	int retry;
	int len = sizeof(struct iphdr) + sizeof(struct icmphdr);
	int fd = icmp_open(timeout);

	for (retry = 0; retry < retries; retry++) {
		icmp_send_ping(fd, (struct sockaddr *) to, sizeof(*to),
			       seq, len);

		if ((len = icmp_read_reply(fd, (struct sockaddr *) &from,
					   sizeof(from), buf, sizeof(buf))) <= 0)
			continue;

		icp = (struct icmphdr *) &buf[ip->ihl * 4];
		if (icp->type == ICMP_ECHOREPLY && icp->un.echo.id == getpid()) {
			icmp_close(fd);
			return 0;
		}
	}
	icmp_close(fd);
	return -1;
}

int usage(const char *program)
{
	fprintf(stderr, "usage: %s [-dh] [-c CONFIG] [-p PIDFILE]\n"
		"options:\n"
       		" -c  Read configuration from FILE (default is " 
			DEFAULT_CONFIG ")\n"
		" -d  Fork to background (damonize)\n"
		" -h  Show this help\n"
		" -p  Use PIDFILE as pidfile (default is " 
			DEFAULT_PIDFILE ")\n"
		"\n",
		program);
	return 1;
}

#if 0
void dump_provider(struct provider *p)
{		
	printf("router:      %s\n"
	       "provider:    %s\n"
	       "interface:   %s\n"
	       "up-action:   %s\n"
	       "down-action: %s\n"
	       "p->status:   %i\n"
	       "\n",
	       inet_ntoa(p->address.sin_addr), p->name, p->interface,
	       p->up_action, p->down_action, p->status);
}
#endif



void ping_loop(struct provider_list *head, int interval)
{
	struct provider *p;
	int seq = 0;
	while (1) {
		seq++;
		SLIST_FOREACH(p, head, provider_list) {
			int status = (do_ping(&p->address, seq, 2, 0.3) == 0);
			if (status != p->status) {
				p->status = status;
				if (status)
					system(p->up_action);
				else
					system(p->down_action);
			}
		}
		sleep(interval);
		seq &= 0xffff;
	}
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
	int c, debug_mode = 0;
	struct provider_list providers;
	char *config_file = DEFAULT_CONFIG;

	while ((c = getopt(argc, argv, "c:dhp:")) != -1) {
		switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			pingu_daemonize++;
			break;
		case 'h':
			return usage(basename(argv[0]));
			return;
		case 'p':
			pid_file = optarg;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	SLIST_INIT(&providers);
	if (read_config(config_file, &providers) == -1)
		return 1;

	if (pingu_daemonize) {
		if (daemonize() == -1)
			return 1;
	}

	ping_loop(&providers, interval);

	return 0;
}
