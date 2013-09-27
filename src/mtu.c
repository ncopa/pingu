#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/sockios.h>
#include <netinet/ip_icmp.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "icmp.h"
#include "netlink.h"

static int fd, mtu_size;
static struct sockaddr_in to;

static void usage(void)
{
	fprintf(stderr,
		"usage: mtu -i <mtu-size> <host>\n"
		"       mtu -I <host>\n"
		"       mtu -d <host>\n"
		"       mtu -D <host>\n"
		"\n"
		" -i <mtu-size>   Inject <mtu-size> as PMTU to <host>\n"
		" -I              Inject local PMTU as PMTU to <host>\n"
		" -d              Discover PMTU to <host>\n"
		" -D              Discover PMTU to <host> and assign it to interface MTU\n"
		"\n");
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

not_mine:
		if ((len = icmp_read_reply(fd, (struct sockaddr *) &from,
					   sizeof(from), buf, sizeof(buf))) <= 0)
			continue;

		if (icmp_parse_reply(buf, len, seq,
				     (struct sockaddr *) &from,
				     (struct sockaddr *) &to))
			goto not_mine;

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

static int discover_mtu(void)
{
	int seq = 1, low_mtu, high_mtu, try_mtu, r;

	/* Check if the host is up */
	if (do_ping(seq++, 0) < 0)
		return -1;

	/* Discover PMTU */
	low_mtu = 68/2;
	high_mtu = 1500/2;
	try_mtu = 1500/2;
	while (1) {
		r = do_ping(seq++, try_mtu * 2);
		if (r > 0 && r < try_mtu * 2) {
			/* pmtu */
			high_mtu = r/2;
			try_mtu = high_mtu;
			continue;
		}
		if (r == 0)
			low_mtu = try_mtu;
		else
			high_mtu = try_mtu - 1;
		if (low_mtu >= high_mtu)
			return 2 * low_mtu;

		try_mtu = low_mtu + (high_mtu - low_mtu + 1) / 2;
	}
}

static void do_discover(void)
{
	int mtu;

	mtu = discover_mtu();
	if (mtu > 0)
		fprintf(stdout, "%d\n", mtu);
	else
		fprintf(stderr, "Host is not up\n");
}

static int set_mtu(const char *dev, int mtu)
{
	struct ifreq ifr;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
		perror("SIOCSIFMTU");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void do_discover_and_write(void)
{
	int mtu;
	char iface[IFNAMSIZ];

	mtu = discover_mtu();
	if (mtu < 0) {
		fprintf(stderr, "Failed to determine MTU\n");
		return;
	}

	if (!netlink_route_get((struct sockaddr *)&to, NULL, iface)) {
		fprintf(stderr, "Failed to determine route interface\n");
		return;
	}

	printf("Writing %d to %s\n", mtu, iface);
	set_mtu(iface, mtu);
}

static void do_inject(void)
{
	__u8 buf[1500];
	struct sockaddr_in from;
	int len, i, seq = 0;

	icmp_send_ping(fd, (struct sockaddr *) &to, sizeof(to),
		       ++seq, mtu_size);
	for (i = 0; i < 5; i++) {
		if ((len = icmp_read_reply(fd, (struct sockaddr *) &from,
					   sizeof(from),
					   buf, sizeof(buf))) <= 0)
			continue;

		if (icmp_parse_reply(buf, len, seq,
				     (struct sockaddr *) &from,
				     (struct sockaddr *) &to))
			continue;

		if (seq != 1)
			sleep(1);

		icmp_send_ping(fd, (struct sockaddr *) &to, sizeof(to),
			       ++seq, mtu_size);
		icmp_send_frag_needed(fd, (struct sockaddr *) &to, sizeof(to),
				      (struct iphdr *) buf, mtu_size - 2);
	}
}

static void do_inject_pmtu(void)
{
	u_int16_t mtu;

	if (!netlink_route_get((struct sockaddr *)&to, &mtu, NULL)) {
		fprintf(stderr, "Failed to determine Path MTU\n");
		return;
	}
	if (mtu == 1500)
		return;

	mtu_size = mtu;
	do_inject();
}

int main(int argc, char **argv)
{
	struct hostent *hp;
	void (*action)(void) = NULL;
	char *target;
	int opt;

	while ((opt = getopt(argc, argv, "DdIi:")) != -1) {
		switch (opt) {
		case 'D':
			action = do_discover_and_write;
			break;
		case 'd':
			action = do_discover;
			break;
		case 'i':
			action = do_inject;
			mtu_size = atoi(optarg);
			break;
		case 'I':
			action = do_inject_pmtu;
			break;
		default:
			usage();
		}
	}

	if (action == NULL || optind >= argc)
		usage();

	target = argv[optind];

	fd = icmp_open(1.0);
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

