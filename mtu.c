#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/ip_icmp.h>

#include "icmp.h"

static int fd, mtu_size;
static struct sockaddr_in to;

static void usage(void)
{
	fprintf(stderr,
		"usage: mtu -i <mtu-size> <host>\n"
		"       mtu -d <host>\n");
	exit(3);
}

static int do_ping(int seq, int size)
{
	__u8 buf[1500];
	struct iphdr *ip = (struct iphdr *) buf;
	struct icmphdr *icp;
	struct sockaddr_in from;
	int len, retry;

	for (retry = 0; retry < 3; retry++) {
		icmp_send_ping(fd, (struct sockaddr *) &to, sizeof(to),
			       seq, size);

		if ((len = icmp_read_reply(fd, (struct sockaddr *) &from,
					   sizeof(from), buf, sizeof(buf))) <= 0)
			continue;

		if (icmp_parse_reply(buf, len, seq,
				     (struct sockaddr *) &from,
				     (struct sockaddr *) &to))
			return -1;

		icp = (struct icmphdr *) &buf[ip->ihl * 4];
		switch (icp->type) {
		case ICMP_ECHOREPLY:
			return 0;
		case ICMP_DEST_UNREACH:
			if (icp->code != ICMP_FRAG_NEEDED)
				return 0;
			return ntohs(icp->un.frag.mtu);
		default:
			return -1;
		}
	}

	return -1;
}

static void do_discover(void)
{
	int seq = 1;
	int low_mtu, high_mtu, try_mtu;

	/* Check if the host is up */
	if (do_ping(seq++, 0) < 0) {
		fprintf(stderr, "Host is not up\n");
		return;
	}

	/* Check if there is no PMTU or if PMTU discovery works */
	low_mtu = do_ping(seq++, 1500);
	if (low_mtu == -1) {
		/* Binary search for working MTU */
		for (low_mtu = 68/2, high_mtu = 1500/2; low_mtu < high_mtu; ) {
			try_mtu = low_mtu + (high_mtu - low_mtu + 1) / 2;
			if (do_ping(seq++, try_mtu * 2) == 0)
				low_mtu = try_mtu;
			else
				high_mtu = try_mtu - 1;
		}
		low_mtu *= 2;
	} else if (low_mtu == 0) {
		low_mtu = 1500;
	}

	fprintf(stdout, "%d\n", low_mtu);
}

static void do_inject(void)
{
	__u8 buf[1500];
	struct sockaddr_in from;
	int len, seq = 0;

	for (;;) {
		icmp_send_ping(fd, (struct sockaddr *) &to, sizeof(to),
			       ++seq, mtu_size);
		if ((len = icmp_read_reply(fd, (struct sockaddr *) &from,
					   sizeof(from),
					   buf, sizeof(buf))) <= 0)
			continue;

		if (icmp_parse_reply(buf, len, seq,
				     (struct sockaddr *) &from,
				     (struct sockaddr *) &to))
			continue;

		icmp_send_frag_needed(fd, (struct sockaddr *) &to, sizeof(to),
				      (struct iphdr *) buf, mtu_size - 2);
		sleep(1);
	}
}

int main(int argc, char **argv)
{
	struct hostent *hp;
	void (*action)(void) = NULL;
	char *target;
	int opt;

	while ((opt = getopt(argc, argv, "di:")) != -1) {
		switch (opt) {
		case 'd':
			action = do_discover;
			break;
		case 'i':
			action = do_inject;
			mtu_size = atoi(optarg);
			break;
		default:
			usage();
		}
	}

	if (action == NULL || optind >= argc)
		usage();

	target = argv[optind];

	fd = icmp_open();
	if (fd < 0)
		exit(1);

	memset((char *) &to, 0, sizeof(to));
	to.sin_family = AF_INET;
	if (inet_aton(target, &to.sin_addr) != 1) {
		hp = gethostbyname(target);
		if (!hp) {
			fprintf(stderr, "mtu: unknown host %s\n", target);
			exit(2);
		}
		memcpy(&to.sin_addr, hp->h_addr, 4);
	}

	action();
}

