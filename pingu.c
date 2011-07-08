
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
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

#if 0
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
#endif

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
	const char *config_file = DEFAULT_CONFIG;
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
	loop = ev_default_loop(0);
	pingu_host_init(loop, config_file);

	if (pingu_daemonize) {
		if (daemonize() == -1)
			return 1;
	}

	ev_run(loop, 0);
	return 0;
}
