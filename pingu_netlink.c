/* pingu_netlink.c - Linux netlink glue
 *
 * Copyright (C) 2007-2009 Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2011 Natanael Copa <ncopa@alpinelinux.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#include <arpa/inet.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/fib_rules.h>
#include <netinet/in.h>

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>

#include <ev.h>

#include "log.h"
#include "pingu_iface.h"
#include "pingu_netlink.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif 

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define NETLINK_KERNEL_BUFFER	(256 * 1024)
#define NETLINK_RECV_BUFFER	(8 * 1024)

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

struct netlink_fd {
	int fd;
	__u32 seq;
	struct ev_io io;

	int dispatch_size;
	const netlink_dispatch_f *dispatch;
};

static const int netlink_groups[] = {
	0,
	RTMGRP_LINK,
	RTMGRP_IPV4_IFADDR,
	RTMGRP_IPV4_ROUTE,
};
static struct netlink_fd netlink_fds[ARRAY_SIZE(netlink_groups)];
#define talk_fd netlink_fds[0]

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

static int netlink_add_rtattr_l(struct nlmsghdr *n, int maxlen, int type,
				const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return FALSE;

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return TRUE;
}

static int netlink_receive(struct netlink_fd *fd, struct nlmsghdr *reply)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int got_reply = FALSE, len;
	char buf[NETLINK_RECV_BUFFER];

	iov.iov_base = buf;
	while (!got_reply) {
		int status;
		struct nlmsghdr *h;

		iov.iov_len = sizeof(buf);
		status = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return reply == NULL;
			log_perror("Netlink overrun");
			continue;
		}

		if (status == 0) {
			log_error("Netlink returned EOF");
			return FALSE;
		}

		h = (struct nlmsghdr *) buf;
		while (NLMSG_OK(h, status)) {
			if (reply != NULL &&
			    h->nlmsg_seq == reply->nlmsg_seq) {
				len = h->nlmsg_len;
				if (len > reply->nlmsg_len) {
					log_error("Netlink message truncated");
					len = reply->nlmsg_len;
				}
				memcpy(reply, h, len);
				got_reply = TRUE;
			} else if (h->nlmsg_type <= fd->dispatch_size &&
				fd->dispatch[h->nlmsg_type] != NULL) {
				fd->dispatch[h->nlmsg_type](h);
			} else if (h->nlmsg_type != NLMSG_DONE) {
				log_info("Unknown NLmsg: 0x%08x, len %d",
					  h->nlmsg_type, h->nlmsg_len);
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	return TRUE;
}

static int netlink_enumerate(struct netlink_fd *fd, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++fd->seq;
	req.g.rtgen_family = family;

	return sendto(fd->fd, (void *) &req, sizeof(req), 0,
		      (struct sockaddr *) &addr, sizeof(addr)) >= 0;
}

int netlink_route_modify(struct netlink_fd *fd, int type,
	in_addr_t destination, uint32_t masklen, in_addr_t gateway, 
	uint32_t metric, int iface_index, int table)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	msg;
		char buf[1024];
	} req;
	struct sockaddr_nl addr;

	memset(&req, 0, sizeof(req));
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_type = type;
	if (type == RTM_NEWROUTE)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

	req.msg.rtm_family = AF_INET;
	req.msg.rtm_table = table;
	req.msg.rtm_dst_len = masklen;
	req.msg.rtm_protocol = RTPROT_BOOT;
	req.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	req.msg.rtm_type = RTN_UNICAST;
	
	netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_DST, &destination, 4);
	netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_OIF, &iface_index, 4);
	netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_GATEWAY, &gateway, 4);
	if (metric != 0)
		netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_PRIORITY, &metric, 4);

	return sendto(fd->fd, (void *) &req, sizeof(req), 0,
		      (struct sockaddr *) &addr, sizeof(addr));

}

int netlink_route_replace_or_add(struct netlink_fd *fd, 
	in_addr_t destination, uint32_t masklen, in_addr_t gateway,
	uint32_t metric, int iface_index, int table)
{
	return netlink_route_modify(fd, RTM_NEWROUTE, destination, masklen,
		gateway, metric, iface_index, table);
}

int netlink_route_delete(struct netlink_fd *fd, 
	in_addr_t destination, uint32_t masklen, in_addr_t gateway, 
	uint32_t metric, int iface_index, int table)
{
	return netlink_route_modify(fd, RTM_DELROUTE, destination, masklen,
		gateway, metric, iface_index, table);
}	

int netlink_rule_modify(struct netlink_fd *fd,
	struct pingu_iface *iface, int type)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	msg;
		char buf[1024];
	} req;
	struct sockaddr_nl addr;
//	uint32_t preference = 1000;
//	in_addr_t destination = 0;

	memset(&req, 0, sizeof(req));
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_type = type;
	if (type == RTM_NEWRULE)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	
	req.msg.rtm_family = AF_INET;
	req.msg.rtm_table = iface->route_table;
	req.msg.rtm_protocol = RTPROT_BOOT;
	req.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	req.msg.rtm_type = RTN_UNICAST;

//	netlink_add_rtattr_l(&req.nlh, sizeof(req), FRA_PRIORITY, &preference, 4);
//	netlink_add_rtattr_l(&req.nlh, sizeof(req), FRA_SRC, &destination, 4);
	netlink_add_rtattr_l(&req.nlh, sizeof(req), FRA_OIFNAME, iface->name, strlen(iface->name)+1);

	return sendto(fd->fd, (void *) &req, sizeof(req), 0,
		      (struct sockaddr *) &addr, sizeof(addr));

}

int netlink_rule_del(struct netlink_fd *fd,	struct pingu_iface *iface)
{
	return netlink_rule_modify(fd, iface, RTM_DELRULE);
}

int netlink_rule_replace_or_add(struct netlink_fd *fd, struct pingu_iface *iface)
{
	netlink_rule_del(fd, iface);
	return netlink_rule_modify(fd, iface, RTM_NEWRULE);
}
	
static void netlink_link_new_cb(struct nlmsghdr *msg)
{
	struct pingu_iface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;

	if (!(ifi->ifi_flags & IFF_LOWER_UP))
		return;

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = pingu_iface_get_by_name(ifname);
	if (iface == NULL)
		return;

	if (iface->index == 0 || (ifi->ifi_flags & ifi->ifi_change & IFF_UP)) {
		log_info("Interface %s: got link",
			  ifname);
	}

	iface->index = ifi->ifi_index;
	iface->has_link = 1;
	pingu_iface_bind_socket(iface, 1);
	netlink_rule_replace_or_add(&talk_fd, iface);
}

static void netlink_link_del_cb(struct nlmsghdr *msg)
{
	struct pingu_iface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = pingu_iface_get_by_name(ifname);
	if (iface == NULL)
		return;

	log_info("Interface '%s' deleted", ifname);
	iface->index = 0;
	iface->has_link = 0;
	netlink_rule_del(&talk_fd, iface);
}

static void netlink_addr_new_cb(struct nlmsghdr *msg)
{
	struct pingu_iface *iface;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];

	if (ifa->ifa_flags & IFA_F_SECONDARY)
		return;

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
	if (rta[IFA_LOCAL] == NULL)
		return;

	iface = pingu_iface_get_by_index(ifa->ifa_index);
	if (iface == NULL || rta[IFA_LOCAL] == NULL)
		return;

	pingu_iface_set_addr(iface, ifa->ifa_family,
			     RTA_DATA(rta[IFA_LOCAL]),
			     RTA_PAYLOAD(rta[IFA_LOCAL]));
}

static void netlink_addr_del_cb(struct nlmsghdr *nlmsg)
{
	struct pingu_iface *iface;
	struct ifaddrmsg *ifa = NLMSG_DATA(nlmsg);
	struct rtattr *rta[IFA_MAX+1];

	if (ifa->ifa_flags & IFA_F_SECONDARY)
		return;

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(nlmsg));
	if (rta[IFA_LOCAL] == NULL)
		return;

	iface = pingu_iface_get_by_index(ifa->ifa_index);
	if (iface == NULL)
		return;

	pingu_iface_set_addr(iface, 0, NULL, 0); 
}

static  void netlink_route_cb_action(struct nlmsghdr *msg, int action)
{
	struct pingu_iface *iface;
	struct rtmsg *rtm = NLMSG_DATA(msg);
	struct rtattr *rta[RTA_MAX+1];

	in_addr_t destination = 0;
	in_addr_t gateway = 0;
	uint32_t metric = 0;
	char deststr[64], gwstr[64];
	char *actionstr = "New";
	if (action == RTM_DELROUTE)
		actionstr = "Delete";
	
	/* ignore route changes that we made ourselves via talk_fd */
	if (msg->nlmsg_pid == getpid())
		return;
		
	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));
	if (rta[RTA_OIF] == NULL || rta[RTA_GATEWAY] == NULL
	    || rtm->rtm_family != PF_INET || rtm->rtm_table != RT_TABLE_MAIN)
		return;

	if (rta[RTA_DST] != NULL)
		destination = *(in_addr_t *)RTA_DATA(rta[RTA_DST]);

	if (rta[RTA_PRIORITY] != NULL)
		metric = *(uint32_t *)RTA_DATA(rta[RTA_PRIORITY]);

	iface = pingu_iface_get_by_index(*(int*)RTA_DATA(rta[RTA_OIF]));
	if (iface == NULL)
		return;

	gateway = *(in_addr_t *)RTA_DATA(rta[RTA_GATEWAY]);

	inet_ntop(rtm->rtm_family, &destination, deststr, sizeof(deststr));
	inet_ntop(rtm->rtm_family, &gateway, gwstr, sizeof(gwstr));

	log_debug("%s route to %s via %s dev %s table %i", actionstr,
		  deststr, gwstr, iface->name, iface->route_table);
	
	netlink_route_modify(&talk_fd, action, destination,
			     rtm->rtm_dst_len, gateway, metric,
			     iface->index, rtm->rtm_table);

	if (destination == 0 && gateway != 0)
		pingu_iface_gateway(iface, rtm->rtm_family, &gateway,
				    metric, action);
}

static void netlink_route_new_cb(struct nlmsghdr *msg)
{
	netlink_route_cb_action(msg, RTM_NEWROUTE);
}


static void netlink_route_del_cb(struct nlmsghdr *msg)
{
	netlink_route_cb_action(msg, RTM_DELROUTE);
}

static const netlink_dispatch_f route_dispatch[RTM_MAX] = {
	[RTM_NEWLINK] = netlink_link_new_cb,
	[RTM_DELLINK] = netlink_link_del_cb,
	[RTM_NEWADDR] = netlink_addr_new_cb,
	[RTM_DELADDR] = netlink_addr_del_cb,
	[RTM_NEWROUTE] = netlink_route_new_cb,
	[RTM_DELROUTE] = netlink_route_del_cb,
};

static void netlink_read_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct netlink_fd *nfd = container_of(w, struct netlink_fd, io);

	if (revents & EV_READ)
		netlink_receive(nfd, NULL);
}

static void netlink_close(struct ev_loop *loop, struct netlink_fd *fd)
{
	if (fd->fd >= 0) {
		ev_io_stop(loop, &fd->io);
		close(fd->fd);
		fd->fd = 0;
	}
}

static int netlink_open(struct ev_loop *loop, struct netlink_fd *fd,
			int protocol, int groups)
{
	struct sockaddr_nl addr;
	int buf = NETLINK_KERNEL_BUFFER;

	fd->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	fd->seq = time(NULL);
	if (fd->fd < 0) {
		log_perror("Cannot open netlink socket");
		return FALSE;
	}

	fcntl(fd->fd, F_SETFD, FD_CLOEXEC);
	if (setsockopt(fd->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
		log_perror("SO_SNDBUF");
		goto error;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
		log_perror("SO_RCVBUF");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = groups;
	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		log_perror("Cannot bind netlink socket");
		goto error;
	}

	ev_io_init(&fd->io, netlink_read_cb, fd->fd, EV_READ);
	ev_io_start(loop, &fd->io);

	return TRUE;

error:
	netlink_close(loop, fd);
	return FALSE;
}


int kernel_init(struct ev_loop *loop)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++) {
		netlink_fds[i].dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
		netlink_fds[i].dispatch = route_dispatch;
		if (!netlink_open(loop, &netlink_fds[i], NETLINK_ROUTE,
				  netlink_groups[i]))
			goto err_close_all;
	}

	netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETLINK);
	netlink_read_cb(loop, &talk_fd.io, EV_READ);

	netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETADDR);
	netlink_read_cb(loop, &talk_fd.io, EV_READ);

	/* man page netlink(7) says that first created netlink socket will
	 * get the getpid() assigned as nlmsg_pid. This is our talk_fd.
	 * 
	 * Our route callbacks will ignore route changes made by ourselves
	 * (nlmsg_pid == getpid()) but we still need to get the initial
	 * route enumration. Therefore we use another netlink socket to
	 * "pretend" that it was not us who created those routes and the
	 * route callback will pick them up.
	 */
	netlink_enumerate(&netlink_fds[1], PF_UNSPEC, RTM_GETROUTE);
	netlink_read_cb(loop, &talk_fd.io, EV_READ);

	return TRUE;

err_close_all:
	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++)
		netlink_close(loop, &netlink_fds[i]);

	return FALSE;
}

