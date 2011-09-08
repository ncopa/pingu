
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "log.h"
#include "pingu_gateway.h"

static void pingu_gateway_add_sorted(struct list_head *gateway_list,
			struct pingu_gateway *new_gw)
{
	struct pingu_gateway *gw;
	list_for_each_entry(gw, gateway_list, gateway_list_entry) {
		if (gw->metric > new_gw->metric) {
			list_add_tail(&new_gw->gateway_list_entry,
				      &gw->gateway_list_entry);
			return;
		}
	}
	list_add_tail(&new_gw->gateway_list_entry, gateway_list);
}

static struct pingu_gateway *pingu_gateway_clone(struct pingu_gateway *gw)
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

static struct pingu_gateway *pingu_gateway_get(struct list_head *gateway_list,
			struct pingu_gateway *gw)
{
	struct pingu_gateway *entry;
	list_for_each_entry(entry, gateway_list, gateway_list_entry) {
		if (gateway_cmp(entry, gw) == 0)
			return entry;
	}
	return NULL;
}

void pingu_gateway_del_all(struct list_head *head)
{
	struct pingu_gateway *gw, *n;
	list_for_each_entry_safe(gw, n, head, gateway_list_entry) {
		list_del(&gw->gateway_list_entry);
		free(gw);
	}
}

void pingu_gateway_add(struct list_head *gateway_list,
			     struct pingu_gateway *gw)
{
	struct pingu_gateway *new_gw = pingu_gateway_clone(gw);
	if (new_gw == NULL)
		return;
	pingu_gateway_add_sorted(gateway_list, new_gw);
}

void pingu_gateway_del(struct list_head *gateway_list,
			     struct pingu_gateway *delete)
{
	struct pingu_gateway *gw = pingu_gateway_get(gateway_list, delete);
	if (gw == NULL)
		return;
	log_debug_gw("removed", gw);
	list_del(&gw->gateway_list_entry);
	free(gw);
}

int is_default_gw(struct pingu_gateway *route)
{
	switch (route->dest.sa.sa_family) {
	case AF_INET:
		return ((route->dest.sin.sin_addr.s_addr == 0) 
			 && (route->gw_addr.sin.sin_addr.s_addr != 0));
		break;
	case AF_INET6:
		log_debug("TODO: ipv6");
		break;
	}
	return 0;
}
		
struct pingu_gateway *pingu_gateway_first_default(struct list_head *gateway_list)
{
	struct pingu_gateway *entry;
	list_for_each_entry(entry, gateway_list, gateway_list_entry) {
		if (is_default_gw(entry))
			return entry;
	}
	return NULL;
}
