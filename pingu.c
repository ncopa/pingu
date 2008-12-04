
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL)
		err(EXIT_FAILURE, "malloc");
	return p;
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
	char **hosts;
	int *offline;
	int hosts_count;
	int interval = 30;
	const char *script = NULL;

	while ((c = getopt(argc, argv, "i:s:")) != -1) {
		switch (c) {
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

	if (argc == 0)
		usage(EXIT_FAILURE);

	offline = xmalloc(sizeof(int) * argc);
	memset(offline, 0, sizeof(int) * argc);

	ping_loop(argv, offline, argc, interval);

	free(hosts);
	return 0;
}
