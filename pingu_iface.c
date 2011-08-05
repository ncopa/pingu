
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

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
#include "pingu_netlink.h"
#include "sockaddr_util.h"

static struct list_head iface_list = LIST_INITIALIZER(iface_list);

#define PINGU_ROUTE_TABLE_MIN 1
#define PINGU_ROUTE_TABLE_MAX 253
unsigned char used_route_table[256];

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
			if (iface->name[0] == '\0')
				return iface;
		} else if (strncmp(name, iface->name, sizeof(iface->name)) == 0) {
			return iface;
		}
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

struct pingu_iface *pingu_iface_get_by_name_or_new(const char *name)
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

	list_init(&iface->ping_list);
	list_init(&iface->gateway_list);
	list_add(&iface->iface_list_entry, &iface_list);
	return iface;
}

void pingu_iface_set_addr(struct pingu_iface *iface, int family,
			  void *data, int len)
{
	sockaddr_init(&iface->primary_addr, family, data);
	if (len <= 0 || data == NULL) {
		pingu_gateway_del_all(&iface->gateway_list);
		log_debug("%s: address removed", iface->name);
		return;
	}
	log_debug("%s: new address: %s", iface->name,
		inet_ntoa(iface->primary_addr.sin.sin_addr));
}

#if 0
void pingu_gateway_dump(struct pingu_iface *iface)
{
	struct pingu_gateway *gw;
	list_for_each_entry(gw, &iface->gateway_list, gateway_list_entry) {
		char buf[64];
		sockaddr_to_string(&gw->gw_addr, buf, sizeof(buf));
		log_debug("dump: %s: via %s metric %i", iface->name, buf,
			  gw->metric);
	}
}
#endif

void pingu_iface_gw_action(struct pingu_iface *iface,
			 struct pingu_gateway *gw, int action)
{
	switch (action) {
	case RTM_NEWROUTE:
		pingu_gateway_add(&iface->gateway_list, gw);
		log_debug("%s: added default gateway", iface->name);
		break;
	case RTM_DELROUTE:
		pingu_gateway_del(&iface->gateway_list, gw);
		log_debug("%s: removed default gateway", iface->name);
		break;
	}
}

void pingu_iface_update_routes(struct pingu_iface *iface, int action)
{
	struct pingu_gateway *route;
	list_for_each_entry(route, &iface->gateway_list, gateway_list_entry) {
		kernel_route_modify(action, route, iface, RT_TABLE_MAIN);
	}
}

int pingu_iface_set_route_table(struct pingu_iface *iface, int table)
{
	static int initialized = 0;
	int i = 1;
	if (!initialized) {
		memset(used_route_table, 0, sizeof(used_route_table));
		initialized = 1;
	}
	if (table == PINGU_ROUTE_TABLE_AUTO) {
		while (i < 253 && used_route_table[i])
			i++;
		table = i;
	}
	if (table < PINGU_ROUTE_TABLE_MIN || table >= PINGU_ROUTE_TABLE_MAX) {
		log_error("Invalid route table %i", table);
		return -1;
	}
	used_route_table[table] = 1;
	iface->route_table = table;
	return table;
}

int pingu_iface_init(struct ev_loop *loop)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (iface->route_table == 0)
			pingu_iface_set_route_table(iface, PINGU_ROUTE_TABLE_AUTO);
		if (pingu_iface_init_socket(loop, iface) == -1)
			return -1;
	}
	return 0;
}
