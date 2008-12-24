#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp.h"

static char *pr_addr(__u32 addr)
{
	struct hostent *hp;
	static char buf[4096];

	sprintf(buf, "%s", inet_ntoa(*(struct in_addr *)&addr));
	return buf;
}

static void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp)
{
	switch (type) {
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
	const u_short *w = addr;
	u_short answer;
	int sum = csum, nleft = len;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return answer;
}


int icmp_parse_reply(__u8 *buf, int len, int seq,
		     struct sockaddr *addr,
		     struct sockaddr *origdest)
{
	struct sockaddr_in *from = (struct sockaddr_in *) addr;
	struct sockaddr_in *to = (struct sockaddr_in *) origdest;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen, csfailed;

	/* Check the IP header */
	ip = (struct iphdr *) buf;
	hlen = ip->ihl * 4;
	if (len < hlen + 8 || ip->ihl < 5)
		return 1;

	/* Now the ICMP part */
	len -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((u_short *)icp, len, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (icp->un.echo.id != getpid() ||
		    ntohs(icp->un.echo.sequence) != seq)
			return 1;			/* 'Twas not our ECHO */

		printf("From %s: icmp_seq=%u bytes=%d\n",
		       pr_addr(from->sin_addr.s_addr),
		       ntohs(icp->un.echo.sequence), len);
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
				if (len < 8 + sizeof(struct iphdr) + 8 ||
				    len < 8 + iph->ihl * 4 + 8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != to->sin_addr.s_addr ||
				    icp1->un.echo.id != getpid() ||
				    ntohs(icp1->un.echo.sequence) != seq)
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

int icmp_send(int fd, struct sockaddr *to, int tolen, void *buf, int buflen)
{
	int i;

	i = sendto(fd, buf, buflen, 0, to, tolen);
	if (i != buflen)
		return -1;

	return 0;
}

int icmp_send_frag_needed(int fd, struct sockaddr *to, int tolen,
			  struct iphdr *iph, int newmtu)
{
	struct sockaddr_in *to_in = (struct sockaddr_in *) to;
	const int len = sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
	char packet[len];
	struct icmphdr *icp;

	icp = (struct icmphdr *) packet;
	icp->type = ICMP_DEST_UNREACH;
	icp->code = ICMP_FRAG_NEEDED;
	icp->checksum = 0;
	icp->un.frag.__unused = 0;
	icp->un.frag.mtu = htons(newmtu);

	/* copy ip header + 64-bits of original packet */
	memcpy(&packet[sizeof(struct icmphdr)], iph,
	       sizeof(struct iphdr) + 8);

	icp->checksum = in_cksum((u_short *) icp, len, 0);

	printf("To %s: frag_needed mtu=%d\n",
	       pr_addr(to_in->sin_addr.s_addr), newmtu);

	return icmp_send(fd, to, tolen, packet, len);
}

int icmp_send_ping(int fd, struct sockaddr *to, int tolen,
		   int seq, int total_size)
{
	struct sockaddr_in *to_in = (struct sockaddr_in *) to;
	char packet[1500];
	struct icmphdr *icp;
	int len;

	if (total_size > sizeof(packet))
		return -1;
	if (total_size < sizeof(struct iphdr) + sizeof(struct icmphdr))
		total_size = sizeof(struct iphdr) + sizeof(struct icmphdr);

	len = total_size - sizeof(struct iphdr);

	icp = (struct icmphdr *) packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(seq);
	icp->un.echo.id = getpid();
	icp->checksum = in_cksum((u_short *) icp, len, 0);

	printf("To %s: icmp_seq=%u bytes=%d\n",
	       pr_addr(to_in->sin_addr.s_addr), seq, len);

	return icmp_send(fd, to, tolen, (void *) packet, len);
}

int icmp_read_reply(int fd, struct sockaddr *from, int fromlen,
		    __u8 *buf, int buflen)
{
	struct iovec iov;
	int len;

	len = recvfrom(fd, buf, buflen, 0, from, &fromlen);
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		return -1;
	}

	return len;
}

int icmp_open(void)
{
	const int pmtudisc = IP_PMTUDISC_DO, yes = 1;
	struct timeval tv;
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		perror("mtuinject: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
		goto err;
	}

	if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER,
		       &pmtudisc, sizeof(pmtudisc)) == -1) {
		perror("ping: IP_MTU_DISCOVER");
		goto err_close;
	}

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		       (char*)&tv, sizeof(tv)) == -1)
		goto err_close;

	return fd;

err_close:
	close(fd);
err:
	return -1;
}

void icmp_close(int fd)
{
	close(fd);
}

