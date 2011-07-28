
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <ev.h>

#include "list.h"
#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_iface.h"
#include "pingu_ping.h"
#include "sockaddr_util.h"

static struct list_head iface_list = LIST_INITIALIZER(iface_list);

static void pingu_iface_socket_cb(struct ev_loop *loop, struct ev_io *w,
				 int revents)
{
	struct pingu_iface *iface = container_of(w, struct pingu_iface, socket_watcher);

	if (revents & EV_READ)
		pingu_ping_read_reply(loop, iface);
}

int pingu_iface_bind_socket(struct pingu_iface *iface, int log_error)
{
	int r;
	if (iface->name[0] == '\0')
		return 0;
	r = setsockopt(iface->fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name,
		       strlen(iface->name));
	if (r < 0 && log_error)
		log_perror(iface->name);
	iface->has_binding = (r == 0);
	return r;
}

static int pingu_iface_init_socket(struct ev_loop *loop,
				   struct pingu_iface *iface)
{
	iface->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (iface->fd < 0) {
		log_perror("socket");
		return -1;
	}

	ev_io_init(&iface->socket_watcher, pingu_iface_socket_cb,
		   iface->fd, EV_READ);
	ev_io_start(loop, &iface->socket_watcher);
	return 0;
}

int pingu_iface_usable(struct pingu_iface *iface)
{
	if (iface->name[0] == '\0')
		return 1;
	return iface->has_link && iface->has_binding;
}

struct pingu_iface *pingu_iface_get_by_name(const char *name)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (name == NULL) {
			if (iface->name[0] == '\n')
				return iface;
		} else if (strncmp(name, iface->name, sizeof(iface->name)) == 0)
			return iface;
	}
	return NULL;
}

struct pingu_iface *pingu_iface_get_by_index(int index)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (iface->index == index)
			return iface;
	}
	return NULL;
}

struct pingu_iface *pingu_iface_new(struct ev_loop *loop, const char *name)
{
	struct pingu_iface *iface = pingu_iface_get_by_name(name);
	if (iface != NULL)
		return iface;

	iface = calloc(1, sizeof(struct pingu_iface));
	if (iface == NULL) {
		log_perror("calloc(iface)");
		return NULL;
	}

	if (name != NULL)
		strlcpy(iface->name, name, sizeof(iface->name));
	
	if (pingu_iface_init_socket(loop, iface) == -1) {
		free(iface);
		return NULL;
	}
	list_init(&iface->ping_list);
	list_add(&iface->iface_list_entry, &iface_list);
	return iface;
}

void pingu_iface_set_addr(struct pingu_iface *iface, int family,
			  void *data, int len)
{
	sockaddr_init(&iface->primary_addr, family, data);
	if (len <= 0 || data == NULL) {
		log_debug("%s: address removed", iface->name);
		return;
	}
	log_debug("%s: new address: %s", iface->name,
		inet_ntoa(iface->primary_addr.sin.sin_addr));
}

void pingu_gateway_add_sorted(struct pingu_iface *iface,
			struct pingu_gateway *new_gw)
{
	struct pingu_gateway *gw;
	list_for_each_entry(gw, &iface->gateway_list, gateway_list_entry) {
		if (gw->metric > new_gw->metric) {
			list_add_tail(&new_gw->gateway_list_entry,
				      &gw->gateway_list_entry);
			return;
		}
	}
	list_add_tail(&new_gw->gateway_list_entry, &iface->gateway_list);
}

struct pingu_gateway *pingu_gateway_new(int family, void *addr,
					int metric)
{
	struct pingu_gateway *gw = calloc(1, sizeof(struct pingu_gateway));
	if (gw == NULL) {
		log_perror("Failed to allocate gateway");
		return NULL;
	}
	gw->gw.sa.sa_family = family;
	gw->metric = metric;
	switch (family) {
	case AF_INET:
		memcpy(&gw->gw.sin.sin_addr, addr,
		       sizeof(gw->gw.sin.sin_addr));
		break;
	case AF_INET6:
		memcpy(&gw->gw.sin6.sin6_addr, addr,
		       sizeof(gw->gw.sin6.sin6_addr));
		break;
	}
	return gw;
}

void pingu_iface_add_gateway(struct pingu_iface *iface, int family,
	void *addr, int metric)
{
	struct pingu_gateway *gw = pingu_gateway_new(family, addr,
						     metric);
	if (gw != NULL)
		pingu_gateway_add_sorted(iface, gw);
}

int pingu_iface_init(struct ev_loop *loop, struct list_head *host_list)
{
	struct pingu_host *host;
	struct pingu_iface *iface;
	int autotbl = 10;
	list_for_each_entry(host, host_list, host_list_entry) {
		iface = pingu_iface_get_by_name(host->interface);
		if (iface == NULL) {
			iface = pingu_iface_new(loop, host->interface);
			iface->route_table = autotbl++;
		}
		if (iface == NULL)
			return -1;
		host->iface = iface;
	}
	return 0;
}

