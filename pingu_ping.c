#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ev.h>

#include "icmp.h"
#include "list.h"
#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_iface.h"
#include "pingu_ping.h"

#define SOCK_ADDR_IN_PTR(sa)	((struct sockaddr_in *)(sa))
#define SOCK_ADDR_IN_ADDR(sa)	SOCK_ADDR_IN_PTR(sa)->sin_addr

#define PING_SEQ_MAX 32000

static int pingu_ping_get_seq(void)
{
	static int seq = 0;
	seq = (seq + 1) % PING_SEQ_MAX;
	return seq;
}

static void pingu_ping_timeout_cb(struct ev_loop *loop, ev_timer *w,
				  int revents)
{
	struct pingu_ping *ping = container_of(w, struct pingu_ping, timeout_watcher);
	log_debug("%s: seq %i (%i/%i) timed out", ping->host->host, ping->seq,
		ping->host->burst.pings_sent, ping->host->max_retries);
	list_del(&ping->ping_list_entry);
	pingu_host_verify_status(loop, ping->host);
	free(ping);
}

static struct pingu_ping *pingu_ping_add(struct ev_loop *loop,
					 struct pingu_host *host, int seq)
{
	struct pingu_ping *ping = calloc(1, sizeof(struct pingu_ping));
	if (ping == NULL)
		return NULL;
	ping->seq = seq;
	ping->host = host;
	ping->host->burst.pings_sent++;
	ev_timer_init(&ping->timeout_watcher, pingu_ping_timeout_cb,
		      host->timeout, 0);
	ev_timer_start(loop, &ping->timeout_watcher);
	list_add(&ping->ping_list_entry, &host->iface->ping_list);
	return ping;
}

static int sockaddr_cmp(struct sockaddr *a, struct sockaddr *b)
{
	if (a->sa_family != b->sa_family)
		return -1;
	switch (a->sa_family) {
	case AF_INET:
		return (SOCK_ADDR_IN_ADDR(a).s_addr - SOCK_ADDR_IN_ADDR(b).s_addr);
		break;
	}
	return -1;
}

static struct pingu_ping *pingu_ping_find(struct icmphdr *icp,
					  struct sockaddr *from,
					  struct list_head *ping_list)
{
	struct pingu_ping *ping;
	if (icp->type != ICMP_ECHOREPLY || icp->un.echo.id != getpid())
		return NULL;
	
	list_for_each_entry(ping, ping_list, ping_list_entry) {
		if (sockaddr_cmp(&ping->host->burst.saddr, from) == 0
		    && ping->seq == ntohs(icp->un.echo.sequence))
			return ping;
	}
	return NULL;
}

static void pingu_ping_handle_reply(struct ev_loop *loop,
				    struct pingu_ping *ping)
{
	log_debug("%s: got seq %i", ping->host->host, ping->seq);
	ping->host->burst.pings_replied++;
	list_del(&ping->ping_list_entry);
	ev_timer_stop(loop, &ping->timeout_watcher);
	pingu_host_verify_status(loop, ping->host);
	free(ping);
}

int pingu_ping_send(struct ev_loop *loop, struct pingu_host *host)
{
	int packetlen = sizeof(struct iphdr) + sizeof(struct icmphdr);
	struct pingu_ping *ping;
	int seq, r;

	seq = pingu_ping_get_seq();
	r = icmp_send_ping(host->iface->fd, &host->burst.saddr,
			       sizeof(host->burst.saddr), seq, packetlen);
	if (r < 0)
		return -1;

	ping = pingu_ping_add(loop, host, seq);
	return ping == NULL ? -1 : 0;
}

void pingu_ping_read_reply(struct ev_loop *loop, struct pingu_iface *iface)
{
	struct sockaddr from;
	unsigned char buf[1500];
	struct iphdr *ip = (struct iphdr *) buf;
	struct pingu_ping *ping;

	int len = icmp_read_reply(iface->fd, &from, sizeof(from), buf,
				  sizeof(buf));
	if (len <= 0)
		return;
	
	ping = pingu_ping_find((struct icmphdr *) &buf[ip->ihl * 4], &from,
			       &iface->ping_list);
	if (ping == NULL)
		return;

	pingu_ping_handle_reply(loop, ping);
}

