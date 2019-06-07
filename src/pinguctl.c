#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "pingu_adm.h"

static int adm_init(const char *socket_path)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_perror("socket");
		return -1;
	}

	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		log_perror(socket_path);
		close(fd);
		return -1;
	}

	return fd;
}

static int adm_send_cmd(int fd, const char *cmd)
{
	char buf[256];
	size_t len;

	snprintf(buf, sizeof(buf), "%s\n", cmd);
	len = strlen(buf);
	if (write(fd, buf, len) != len)
		return -1;
	return len;
}

static int adm_recv(int fd)
{
	char buf[1024];
	int n, total = 0;

	while (1) {
		n = recv(fd, buf, sizeof(buf), 0);
		if (n <= 0)
			break;
		write(STDOUT_FILENO, buf, n);
		total += n;
	}
	return total;
}

int main(int argc, char *argv[])
{
	const char *socket_path = DEFAULT_ADM_SOCKET;
	int i, fd;

	while ((i = getopt(argc, argv, "a:")) != -1) {
		switch (i) {
		case 'a':
			socket_path = optarg;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	log_init("pinguctl", 0);
	fd = adm_init(socket_path);
	if (fd < 0)
		return 1;

	for (i = 0; i < argc; i++) {
		if (adm_send_cmd(fd, argv[i]) < 0 || adm_recv(fd) < 0)
			return 1;
	}

	close(fd);
	return 0;
}
