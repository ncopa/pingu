#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

struct sockaddr_in whereto;
u_char inpack[0x10000];
u_char outpack[0x10000];
int mtu_size;

static char *pr_addr(__u32 addr)
{
	struct hostent *hp;
	static char buf[4096];

	sprintf(buf, "%s", inet_ntoa(*(struct in_addr *)&addr));
	return buf;
}

static void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp)
{
	switch(type) {
	case ICMP_ECHOREPLY:
		printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(code) {
		case ICMP_NET_UNREACH:
			printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			printf("Frag needed and DF set (mtu = %u)\n", info);
			break;
		case ICMP_SR_FAILED:
			printf("Source Route Failed\n");
			break;
		case ICMP_PKT_FILTERED:
			printf("Packet filtered\n");
			break;
		default:
			printf("Dest Unreachable, Bad Code: %d\n", code);
			break;
		}
		break;
	case ICMP_SOURCE_QUENCH:
		printf("Source Quench\n");
		break;
	case ICMP_REDIRECT:
		switch(code) {
		case ICMP_REDIR_NET:
			printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			printf("Redirect Type of Service and Host");
			break;
		default:
			printf("Redirect, Bad Code: %d", code);
			break;
		}
		if (icp)
			printf("(New nexthop: %s)\n", pr_addr(icp->un.gateway));
		break;
	case ICMP_ECHO:
		printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			printf("Frag reassembly time exceeded\n");
			break;
		default:
			printf("Time exceeded, Bad Code: %d\n", code);
			break;
		}
		break;
	case ICMP_PARAMETERPROB:
		printf("Parameter problem: pointer = %u\n", icp ? (ntohl(icp->un.gateway)>>24) : info);
		break;
	case ICMP_TIMESTAMP:
		printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf("Address Mask Reply\n");
		break;
#endif
	default:
		printf("Bad ICMP type: %d\n", type);
	}
}

static u_short in_cksum(const u_short *addr, register int len, u_short csum)
{
	register int nleft = len;
	const u_short *w = addr;
	register u_short answer;
	register int sum = csum;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

int send_probe(int icmp_sock, int *seq)
{
	struct icmphdr *icp;
	int i, cc = mtu_size - sizeof(struct iphdr);

	icp = (struct icmphdr *)outpack;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(++(*seq));
	icp->un.echo.id = getpid();
	icp->checksum = in_cksum((u_short *)icp, cc, 0);

	printf("To %s: icmp_seq=%u bytes=%d\n",
	       pr_addr(whereto.sin_addr.s_addr),
	       ntohs(icp->un.echo.sequence), cc);

	i = sendto(icmp_sock, outpack, cc, 0,
		   (struct sockaddr *) &whereto, sizeof(whereto));

	return (cc == i ? 0 : i);
}

int send_frag_needed(int icmp_sock, struct iphdr *iph, int newmtu)
{
	struct icmphdr *icp;
	int i, cc = sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

	icp = (struct icmphdr *) outpack;
	icp->type = ICMP_DEST_UNREACH;
	icp->code = ICMP_FRAG_NEEDED;
	icp->checksum = 0;
	icp->un.frag.__unused = 0;
	icp->un.frag.mtu = htons(newmtu);

	/* copy ip header + 64-bits of original packet */
	memcpy(icp + 1, iph, sizeof(struct iphdr) + 8);

	icp->checksum = in_cksum((u_short *)icp, cc, 0);

	printf("To %s: frag_needed mtu=%d\n",
	       pr_addr(whereto.sin_addr.s_addr),
	       mtu_size - 2);

	i = sendto(icmp_sock, outpack, cc, 0,
		   (struct sockaddr *) &whereto, sizeof(whereto));

	return (cc == i ? 0 : i);
}

/*
 * parse_reply --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
int
parse_reply(int icmp_sock, __u8 *buf, int cc, void *addr)
{
	struct sockaddr_in *from = addr;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int csfailed;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	hlen = ip->ihl*4;
	if (cc < hlen + 8 || ip->ihl < 5) {
		return 1;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((u_short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (icp->un.echo.id != getpid())
			return 1;			/* 'Twas not our ECHO */

		printf("From %s: icmp_seq=%u bytes=%d\n",
		       pr_addr(from->sin_addr.s_addr),
		       ntohs(icp->un.echo.sequence),
		       cc);

		if (cc+hlen >= mtu_size - 2)
			send_frag_needed(icmp_sock, ip, mtu_size - 2);
	} else {
		/* We fall here when a redirect or source quench arrived.
		 * Also this branch processes icmp errors, when IP_RECVERR
		 * is broken. */

		switch (icp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr * iph = (struct  iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr*)((unsigned char *)iph + iph->ihl*4);
				int error_pkt;
				if (cc < 8+sizeof(struct iphdr)+8 ||
				    cc < 8+iph->ihl*4+8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != whereto.sin_addr.s_addr ||
				    icp1->un.echo.id != getpid())
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					//acknowledge(ntohs(icp1->un.echo.sequence));
				}

				printf("From %s: icmp_seq=%u ",
				       pr_addr(from->sin_addr.s_addr),
				       ntohs(icp1->un.echo.sequence));
				if (csfailed)
					printf("(BAD CHECKSUM)");
				pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp);
				return !error_pkt;
			}
		default:
			/* MUST NOT */
			break;
		}
		printf("From %s: ", pr_addr(from->sin_addr.s_addr));
		pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp);
		return 0;
	}

	return 0;
}

static int read_reply(int icmp_sock, __u8 *packet, int packlen)
{
	struct iovec iov;
	char addrbuf[128];
	socklen_t addrlen = sizeof(addrbuf);
	int cc;

	cc = recvfrom(icmp_sock, packet, packlen, 0,
		      (struct sockaddr *) addrbuf, &addrlen);
	if (cc < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		return -1;
	}

	parse_reply(icmp_sock, packet, cc, addrbuf);
}

int main(int argc, char **argv)
{
	int pmtudisc = IP_PMTUDISC_DO;
	int yes = 1;
	int icmp_sock, raw_sock, seq = 0;
	char *target;
	struct hostent *hp;

	mtu_size = 1400;

	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_sock < 0) {
		perror("mtuinject: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
		exit(1);
	}

	if (setsockopt(icmp_sock, SOL_IP, IP_MTU_DISCOVER,
		       &pmtudisc, sizeof(pmtudisc)) == -1) {
		perror("ping: IP_MTU_DISCOVER");
		exit(2);
	}

	if (argc > 1)
		target = argv[1];
	else {
		fprintf(stderr, "usage: %s <host>\n", argv[0]);
		exit(3);
	}

	memset((char *)&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	if (inet_aton(target, &whereto.sin_addr) != 1) {
		hp = gethostbyname(target);
		if (!hp) {
			fprintf(stderr, "ping: unknown host %s\n", target);
			exit(2);
		}
		memcpy(&whereto.sin_addr, hp->h_addr, 4);
	}

	printf("Injecting path MTU %d to %s\n",
	       mtu_size - 2, pr_addr(whereto.sin_addr.s_addr));
	send_probe(icmp_sock, &seq);

	for (;;) {
		send_probe(icmp_sock, &seq);
		read_reply(icmp_sock, inpack, sizeof(inpack));
		sleep(1);
	}
}

