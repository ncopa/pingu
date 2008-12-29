#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))

struct netlink_fd {
	int fd;
	__u32 seq;
};

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

static int netlink_add_rtaddr_l(struct nlmsghdr *n, int maxlen, int type,
				const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *) addr;
		return netlink_add_rtattr_l(n, maxlen, type, &sin->sin_addr,
					    sizeof(sin->sin_addr));
		}
	default:
		return FALSE;
	}
}

static void netlink_close(struct netlink_fd *fd)
{
	if (fd->fd >= 0) {
		close(fd->fd);
		fd->fd = 0;
	}
}

static int netlink_open(struct netlink_fd *fd)
{
	int buf = 16 * 1024;

	fd->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	fd->seq = time(NULL);
	if (fd->fd < 0) {
		perror("Cannot open netlink socket");
		return FALSE;
	}

	fcntl(fd->fd, F_SETFD, FD_CLOEXEC);
	if (setsockopt(fd->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
		perror("SO_SNDBUF");
		goto error;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
		perror("SO_RCVBUF");
		goto error;
	}
	return TRUE;

error:
	netlink_close(fd);
	return FALSE;
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
	char buf[16*1024];

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
			fprintf(stderr, "Netlink overrun\n");
			continue;
		}

		if (status == 0) {
			fprintf(stderr, "Netlink returned EOF\n");
			return FALSE;
		}

		h = (struct nlmsghdr *) buf;
		while (NLMSG_OK(h, status)) {
			if (reply != NULL &&
			    h->nlmsg_seq == reply->nlmsg_seq) {
				len = h->nlmsg_len;
				if (len > reply->nlmsg_len) {
					fprintf(stderr, "Netlink message "
						"truncated\n");
					len = reply->nlmsg_len;
				}
				memcpy(reply, h, len);
				got_reply = TRUE;
			} else if (h->nlmsg_type != NLMSG_DONE) {
				fprintf(stderr,
					"Unknown NLmsg: 0x%08x, len %d\n",
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
		fprintf(stderr, "Cannot talk to rtnetlink\n");
		return FALSE;
	}
	return TRUE;
}

static int netlink_talk(struct nlmsghdr *req, size_t replysize,
			struct nlmsghdr *reply)
{
	struct netlink_fd fd;
	int ret = FALSE;

	if (!netlink_open(&fd))
		return FALSE;

	if (reply == NULL)
		req->nlmsg_flags |= NLM_F_ACK;

	if (!netlink_send(&fd, req))
		goto out;

	if (reply != NULL) {
		reply->nlmsg_len = replysize;
		ret = netlink_receive(&fd, reply);
	} else {
		ret = TRUE;
	}
out:
	netlink_close(&fd);
	return ret;
}

int netlink_route_get(struct sockaddr *dst, u_int16_t *mtu)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;
	struct rtmsg *r = NLMSG_DATA(&req.n);
	struct rtattr *rta[RTA_MAX+1];
	struct rtattr *rtax[RTAX_MAX+1];

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = dst->sa_family;

	netlink_add_rtaddr_l(&req.n, sizeof(req), RTA_DST, dst);
	req.r.rtm_dst_len = 32;

	if (!netlink_talk(&req.n, sizeof(req), &req.n))
		return FALSE;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));
	if (rta[RTA_METRICS] == NULL)
		return FALSE;

	netlink_parse_rtattr(rtax, RTAX_MAX, RTA_DATA(rta[RTA_METRICS]),
			     RTA_PAYLOAD(rta[RTA_METRICS]));
	if (rtax[RTAX_MTU] == NULL)
		return FALSE;

	*mtu = *(int*) RTA_DATA(rtax[RTAX_MTU]);
	return TRUE;
}
