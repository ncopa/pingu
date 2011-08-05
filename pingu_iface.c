
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

void pingu_iface_flush_gateways(struct pingu_iface *iface)
{
	struct pingu_gateway *gw, *n;
	list_for_each_entry_safe(gw, n, &iface->gateway_list, gateway_list_entry) {
		list_del(&gw->gateway_list_entry);
		free(gw);	
	}	
}

void pingu_iface_set_addr(struct pingu_iface *iface, int family,
			  void *data, int len)
{
	sockaddr_init(&iface->primary_addr, family, data);
	if (len <= 0 || data == NULL) {
		pingu_iface_flush_gateways(iface);
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

void pingu_iface_gateway_dump(struct pingu_iface *iface)
{
	struct pingu_gateway *gw;
	list_for_each_entry(gw, &iface->gateway_list, gateway_list_entry) {
		char buf[64];
		sockaddr_to_string(&gw->gw_addr, buf, sizeof(buf));
		log_debug("dump: %s: via %s metric %i", iface->name, buf,
			  gw->metric);
	}
}

struct pingu_gateway *pingu_gateway_clone(struct pingu_gateway *gw)
{
	struct pingu_gateway *new_gw = calloc(1, sizeof(struct pingu_gateway));
	if (gw == NULL) {
		log_perror("Failed to allocate gateway");
		return NULL;
	}
	/* copy the fields without overwriting the list entry */
	memcpy(&new_gw->dest, &gw->dest, sizeof(new_gw->dest));
	memcpy(&new_gw->gw_addr, &gw->gw_addr, sizeof(new_gw->gw_addr));
	new_gw->dst_len = gw->dst_len;
	new_gw->src_len = gw->src_len;
	new_gw->metric = gw->metric;
	new_gw->protocol = gw->protocol;
	new_gw->scope = gw->scope;
	new_gw->type = gw->type;
	return new_gw;
}

static void log_debug_gw(char *msg, struct pingu_gateway *gw)
{
	char destbuf[64], gwaddrbuf[64];
	log_debug("%s: %s/%i via %s metric %i", msg,
		  sockaddr_to_string(&gw->dest, destbuf, sizeof(destbuf)),
		  gw->dst_len,
		  sockaddr_to_string(&gw->gw_addr, gwaddrbuf, sizeof(gwaddrbuf)),
		  gw->metric);
}

static int gateway_cmp(struct pingu_gateway *a, struct pingu_gateway *b)
{
	int r;
	if (a->dst_len != b->dst_len)
		return a->dst_len - b->dst_len;
	r = sockaddr_cmp(&a->dest, &b->dest);
	if (r != 0)
		return r;
	r = sockaddr_cmp(&a->gw_addr, &b->gw_addr);
	if (r != 0)
		return r;
	return a->metric - b->metric;
}
	
static struct pingu_gateway *pingu_gateway_get(struct pingu_iface *iface,
			struct pingu_gateway *gw)
{
	struct pingu_gateway *entry;
	list_for_each_entry(entry, &iface->gateway_list, gateway_list_entry) {
		if (gateway_cmp(entry, gw) == 0)
			return entry;
	}
	return NULL;
}

void pingu_iface_add_gateway(struct pingu_iface *iface,
			     struct pingu_gateway *gw)
{
	struct pingu_gateway *new_gw = pingu_gateway_clone(gw);
	if (new_gw == NULL)
		return;
	pingu_gateway_add_sorted(iface, new_gw);
	log_debug("%s: added default gateway", iface->name);
}

void pingu_iface_del_gateway(struct pingu_iface *iface,
			     struct pingu_gateway *delete)
{
	struct pingu_gateway *gw = pingu_gateway_get(iface, delete);
	if (gw == NULL)		
		return;
	log_debug_gw("removed", gw);
	list_del(&gw->gateway_list_entry);
	free(gw); 
}

void pingu_iface_gw_action(struct pingu_iface *iface, 
			 struct pingu_gateway *gw, int action)
{
	switch (action) {
	case RTM_NEWROUTE:
		pingu_iface_add_gateway(iface, gw);
		break;
	case RTM_DELROUTE:
		pingu_iface_del_gateway(iface, gw);
		break;
	}
	pingu_iface_gateway_dump(iface);
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
