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

static int netlink_add_rtattr_addr_any(struct nlmsghdr *n, int maxlen,
					int type, union sockaddr_any *sa)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		return netlink_add_rtattr_l(n, maxlen, type, &sa->sin.sin_addr, 4);
		break;
	case AF_INET6:
		return netlink_add_rtattr_l(n, maxlen, type, &sa->sin6.sin6_addr, 16);
		break;
	}
	return FALSE;
}

static int netlink_add_subrtattr_l(struct rtattr *rta, int maxlen, int type,
				   const void *data, int alen)
{
        struct rtattr *subrta;
        int len = RTA_LENGTH(alen);

        if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen)
		return FALSE;

        subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
        subrta->rta_type = type;
        subrta->rta_len = len;
        memcpy(RTA_DATA(subrta), data, alen);
        rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
        return TRUE;
}

static int netlink_add_subrtattr_addr_any(struct rtattr *rta, int maxlen,
					int type, union sockaddr_any *sa)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		return netlink_add_subrtattr_l(rta, maxlen, type, &sa->sin.sin_addr, 4);
		break;
	case AF_INET6:
		return netlink_add_subrtattr_l(rta, maxlen, type, &sa->sin6.sin6_addr, 16);
		break;
	}
	return FALSE;
}

static int netlink_get_error(struct nlmsghdr *hdr)
{
	struct nlmsgerr *nlerr = (struct nlmsgerr*)NLMSG_DATA(hdr);
	if (hdr->nlmsg_type != NLMSG_ERROR)
		return 0;
	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		log_error("Netlink error message truncated");
		return -1;
	}
	return -nlerr->error;
}

static int netlink_log_error(struct nlmsghdr *hdr)
{
	int err = netlink_get_error(hdr);
	if (err > 0)
		log_error("Netlink error: %s", strerror(err));
	return err;
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
			} else if (h->nlmsg_type == NLMSG_ERROR) {
				return netlink_log_error(h);
			} else if (h->nlmsg_type != NLMSG_DONE) {
				log_info("Unknown NLmsg: 0x%08x, len %d",
					  h->nlmsg_type, h->nlmsg_len);
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	return TRUE;
}

static int netlink_send(struct netlink_fd *fd, struct nlmsghdr *req)
{
        struct sockaddr_nl nladdr;
        struct iovec iov = {
                .iov_base = (void*) req,
                .iov_len = req->nlmsg_len
        };
        struct msghdr msg = {
                .msg_name = &nladdr,
                .msg_namelen = sizeof(nladdr),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        int status;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        req->nlmsg_seq = ++fd->seq;

        status = sendmsg(fd->fd, &msg, 0);
        if (status < 0) {
                log_perror("Cannot talk to rtnetlink");
                return FALSE;
        }
        return TRUE;
}

static int netlink_talk(struct netlink_fd *fd, struct nlmsghdr *req,
		 size_t replysize, struct nlmsghdr *reply)
{
	if (reply == NULL)
		req->nlmsg_flags |= NLM_F_ACK;

	if (!netlink_send(fd, req))
		return FALSE;

	if (reply == NULL)
		return TRUE;

	reply->nlmsg_len = replysize;
	return netlink_receive(fd, reply);
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

int netlink_route_modify(struct netlink_fd *fd, int action_type,
			  struct pingu_gateway *route,
			  int iface_index, int table)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	msg;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_type = action_type;
	if (action_type == RTM_NEWROUTE)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

	req.msg.rtm_family = route->dest.sa.sa_family;
	req.msg.rtm_table = table;
	req.msg.rtm_dst_len = route->dst_len;
	req.msg.rtm_protocol = route->protocol;
	req.msg.rtm_scope = route->scope;
	req.msg.rtm_type = route->type;

	netlink_add_rtattr_addr_any(&req.nlh, sizeof(req), RTA_DST,
					&route->dest);
	netlink_add_rtattr_addr_any(&req.nlh, sizeof(req), RTA_GATEWAY,
					&route->gw_addr);
	netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_OIF, &iface_index, 4);
	if (route->metric != 0)
		netlink_add_rtattr_l(&req.nlh, sizeof(req), RTA_PRIORITY,
				     &route->metric, 4);

	if (!netlink_talk(fd, &req.nlh, sizeof(req), &req.nlh))
		return FALSE;
	return netlink_get_error(&req.nlh);
}

static int add_one_nh(struct rtattr *rta, struct rtnexthop *rtnh,
		      struct pingu_iface *iface,
		      struct pingu_gateway *route)
{
	if (route == NULL)
		return 0;
	netlink_add_subrtattr_addr_any(rta, 1024, RTA_GATEWAY,
					&route->gw_addr);
	rtnh->rtnh_len += sizeof(struct rtattr) + 4; // TODO: support ipv6
	if (iface->balance_weight)
		rtnh->rtnh_hops = iface->balance_weight - 1;
	rtnh->rtnh_ifindex = iface->index;
	return 1;
}

static int add_nexthops(struct nlmsghdr *nlh, size_t nlh_size,
			 struct list_head *iface_list, int action_type)
{
	char buf[1024];
	struct rtattr *rta = (void *)buf;
	struct rtnexthop *rtnh;
	struct pingu_iface *iface;
	struct pingu_gateway *route;
	int count = 0;

	memset(buf, 0, sizeof(buf));
	rta->rta_type = RTA_MULTIPATH;
	rta->rta_len = RTA_LENGTH(0);
	rtnh = RTA_DATA(rta);

	list_for_each_entry(iface, iface_list, iface_list_entry) {
		route = pingu_gateway_first_default(&iface->gateway_list);
		switch (action_type) {
		case RTM_NEWROUTE:
			if ((!iface->balance) || iface->index == 0
			    || route == NULL)
				continue;
			iface->has_multipath = 1;
			break;
		case RTM_DELROUTE:
			if (!iface->has_multipath)
				continue;
			iface->has_multipath = 0;
			break;
		}
		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_len = sizeof(*rtnh);
		rta->rta_len += rtnh->rtnh_len;
		count += add_one_nh(rta, rtnh, iface, route);
		rtnh = RTNH_NEXT(rtnh);
	}
	if (rta->rta_len > RTA_LENGTH(0))
		netlink_add_rtattr_l(nlh, nlh_size, RTA_MULTIPATH,
				     RTA_DATA(rta), RTA_PAYLOAD(rta));
	return count;
}

int netlink_route_multipath(struct netlink_fd *fd, int action_type,
			    struct list_head *iface_list, int table)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	msg;
		char buf[1024];
	} req;
	union sockaddr_any dest;
	int count = 0;

	memset(&req, 0, sizeof(req));
	memset(&dest, 0, sizeof(dest));
	dest.sa.sa_family = AF_INET;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_type = action_type;
	if (action_type == RTM_NEWROUTE)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

	req.msg.rtm_family = AF_INET;
	req.msg.rtm_table = table;
	req.msg.rtm_dst_len = 0;
	req.msg.rtm_protocol = RTPROT_BOOT;
	req.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	req.msg.rtm_type = RTN_UNICAST;

	netlink_add_rtattr_addr_any(&req.nlh, sizeof(req), RTA_DST,
					&dest);

	count = add_nexthops(&req.nlh, sizeof(req), iface_list, action_type);
	if (count == 0)
		return 0;

	if (!netlink_talk(fd, &req.nlh, sizeof(req), &req.nlh))
		return -1;
	return netlink_get_error(&req.nlh);
}

int netlink_route_replace_or_add(struct netlink_fd *fd,
				 struct pingu_gateway *route,
				 int iface_index, int table)
{
	return netlink_route_modify(fd, RTM_NEWROUTE, route, iface_index, table);
}

int netlink_route_delete(struct netlink_fd *fd,
			 struct pingu_gateway *route,
			 int iface_index, int table)
{
	return netlink_route_modify(fd, RTM_DELROUTE, route, iface_index, table);
}

static void netlink_route_flush(struct netlink_fd *fd, struct pingu_iface *iface)
{
	struct pingu_gateway *gw;
	int err;
	list_for_each_entry(gw, &iface->gateway_list, gateway_list_entry) {
		err = netlink_route_delete(fd, gw, iface->index, iface->route_table);
		if (err > 0)
			log_error("%s: Failed to clean up route in table %i: ",
				  iface->name, iface->route_table, strerror(err));
	}
}

int netlink_rule_modify(struct netlink_fd *fd,
	struct pingu_iface *iface, int type)
{
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	msg;
		char buf[1024];
	} req;
	char buf[64];

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_type = type;
	if (type == RTM_NEWRULE)
		req.nlh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

	req.msg.rtm_family = AF_INET;
	req.msg.rtm_table = iface->route_table;
	req.msg.rtm_protocol = RTPROT_BOOT;
	req.msg.rtm_scope = RT_SCOPE_UNIVERSE;
	req.msg.rtm_type = RTN_UNICAST;

	req.msg.rtm_src_len = 32;
	netlink_add_rtattr_addr_any(&req.nlh, sizeof(req), FRA_SRC,
				    &iface->primary_addr);
	sockaddr_to_string(&iface->primary_addr, buf, sizeof(buf));

	if (!netlink_talk(fd, &req.nlh, sizeof(req), &req.nlh))
		return -1;

	return netlink_get_error(&req.nlh);
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

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = pingu_iface_get_by_name(ifname);
	if (iface == NULL)
		return;

	if (iface->index == 0 && ifi->ifi_index != 0)
		log_info("New interface: %s", ifname);

	iface->index = ifi->ifi_index;
	if (ifi->ifi_flags & IFF_LOWER_UP) {
		log_info("%s: got link", ifname);
		iface->has_link = 1;
	}
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
}

static void netlink_addr_new_cb(struct nlmsghdr *msg)
{
	struct pingu_iface *iface;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];
	int err;

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
	pingu_iface_bind_socket(iface, 1);
	err = netlink_rule_replace_or_add(&talk_fd, iface);
	if (err == 0)
		iface->has_route_rule = 1;
	if (err > 0)
		log_error("%s: Failed to add route rule: %s", iface->name,
			  strerror(err));
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

	netlink_rule_del(&talk_fd, iface);
	pingu_iface_set_addr(iface, 0, NULL, 0);
}

static struct pingu_gateway *gw_from_rtmsg(struct pingu_gateway *gw,
					      struct rtmsg *rtm,
					      struct rtattr **rta)
{
	memset(gw, 0, sizeof(*gw));
	gw->dst_len = rtm->rtm_dst_len;
	gw->src_len = rtm->rtm_src_len;
	gw->dest.sa.sa_family = rtm->rtm_family;
	gw->protocol = rtm->rtm_protocol;
	gw->scope = rtm->rtm_scope;
	gw->type = rtm->rtm_type;

	if (rta[RTA_SRC] != NULL)
		sockaddr_init(&gw->src, rtm->rtm_family, RTA_DATA(rta[RTA_SRC]));

	if (rta[RTA_DST] != NULL)
		sockaddr_init(&gw->dest, rtm->rtm_family, RTA_DATA(rta[RTA_DST]));

	if (rta[RTA_PRIORITY] != NULL)
		gw->metric = *(uint32_t *)RTA_DATA(rta[RTA_PRIORITY]);

	if (rta[RTA_GATEWAY] != NULL)
		sockaddr_init(&gw->gw_addr, rtm->rtm_family, RTA_DATA(rta[RTA_GATEWAY]));
	return gw;
}

static void log_route_change(struct pingu_gateway *route,
			     char *ifname, int table, int action)
{
	char deststr[64] = "", gwstr[64] = "", viastr[68] = "";
	char *actionstr = "New";
	if (action == RTM_DELROUTE)
		actionstr = "Delete";

	sockaddr_to_string(&route->dest, deststr, sizeof(deststr));
	sockaddr_to_string(&route->gw_addr, gwstr, sizeof(gwstr));
	if (gwstr[0] != '\0')
		snprintf(viastr, sizeof(viastr), "via %s ", gwstr);
	log_debug("%s route to %s/%i %sdev %s table %i", actionstr,
		  deststr, route->dst_len, viastr, ifname, table);
}

static void netlink_route_cb_action(struct nlmsghdr *msg, int action)
{
	struct pingu_iface *iface;
	struct rtmsg *rtm = NLMSG_DATA(msg);
	struct rtattr *rta[RTA_MAX+1];

	struct pingu_gateway route;
	int err = 0;

	/* ignore route changes that we made ourselves via talk_fd */
	if (msg->nlmsg_pid == getpid())
		return;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));
	if (rta[RTA_OIF] == NULL || rtm->rtm_family != PF_INET
	    || rtm->rtm_table != RT_TABLE_MAIN)
		return;

	gw_from_rtmsg(&route, rtm, rta);
	iface = pingu_iface_get_by_index(*(int*)RTA_DATA(rta[RTA_OIF]));
	if (iface == NULL)
		return;

	log_route_change(&route, iface->name, iface->route_table, action);
	/* Kernel will remove the alternate route when we lose the
	 * address so we don't need try remove it ourselves */
	if (action != RTM_DELROUTE || iface->has_address)
		err = netlink_route_modify(&talk_fd, action, &route,
					   iface->index, iface->route_table);
	if (err > 0)
		log_error("Failed to %s route to table %i",
			  action == RTM_NEWROUTE ? "add" : "delete",
			  iface->route_table);
	pingu_iface_gw_action(iface, &route, action);
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
		if (loop != NULL)
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


int kernel_route_modify(int action, struct pingu_gateway *route,
			struct pingu_iface *iface, int table)
{
	log_route_change(route, iface->name, table, action);
	return netlink_route_modify(&talk_fd, action, route, iface->index, table);
}

int kernel_route_multipath(int action, struct list_head *iface_list, int table)
{
	return netlink_route_multipath(&talk_fd, action, iface_list, table);
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

void kernel_cleanup_iface_routes(struct pingu_iface *iface)
{
	int err = 0;
	if (iface->has_route_rule) {
		err = netlink_rule_del(&talk_fd, iface);
		if (err == 0)
			iface->has_route_rule = 0;
		if (err > 0)
			log_error("Failed to delete route rule for %s", iface->name);
		netlink_route_flush(&talk_fd, iface);
	}
}

void kernel_close(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++)
		netlink_close(NULL, &netlink_fds[i]);
}

