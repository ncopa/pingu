
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "log.h"
#include "pingu_route.h"

static void pingu_route_add_sorted(struct list_head *route_list,
			struct pingu_route *new_gw)
{
	struct pingu_route *gw;
	list_for_each_entry(gw, route_list, route_list_entry) {
		if (gw->metric > new_gw->metric) {
			list_add_tail(&new_gw->route_list_entry,
				      &gw->route_list_entry);
			return;
		}
	}
	list_add_tail(&new_gw->route_list_entry, route_list);
}

static struct pingu_route *pingu_route_clone(struct pingu_route *gw)
{
	struct pingu_route *new_gw = calloc(1, sizeof(struct pingu_route));
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

char *pingu_route_to_string(struct pingu_route *route,
			    char *buf, size_t bufsize)
{
	char deststr[64] = "", gwstr[64] = "", viastr[68] = "";
	char ifname[IF_NAMESIZE] = "", devstr[IF_NAMESIZE + 5] = "";

	sockaddr_to_string(&route->dest, deststr, sizeof(deststr));
	sockaddr_to_string(&route->gw_addr, gwstr, sizeof(gwstr));
	if (gwstr[0] != '\0')
		snprintf(viastr, sizeof(viastr), "via %s ", gwstr);
	if (if_indextoname(route->dev_index, ifname) != NULL)
		snprintf(devstr, sizeof(devstr), "dev %s ", ifname);
		
	snprintf(buf, bufsize, "%s/%i %s%smetric %i", deststr,
		 route->dst_len, viastr, devstr, route->metric);
	return buf;
}

static void log_debug_gw(char *msg, struct pingu_route *gw)
{
	char routestr[512] = "";
	log_debug("%s: %s", msg,
		  pingu_route_to_string(gw, routestr, sizeof(routestr)));
}

static int gateway_cmp(struct pingu_route *a, struct pingu_route *b)
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

static struct pingu_route *pingu_route_get(struct list_head *route_list,
			struct pingu_route *gw)
{
	struct pingu_route *entry;
	list_for_each_entry(entry, route_list, route_list_entry) {
		if (gateway_cmp(entry, gw) == 0)
			return entry;
	}
	return NULL;
}

void pingu_route_del_all(struct list_head *head)
{
	struct pingu_route *gw, *n;
	list_for_each_entry_safe(gw, n, head, route_list_entry) {
		list_del(&gw->route_list_entry);
		free(gw);
	}
}

void pingu_route_add(struct list_head *route_list,
			     struct pingu_route *gw)
{
	struct pingu_route *new_gw = pingu_route_clone(gw);
	if (new_gw == NULL)
		return;
	pingu_route_add_sorted(route_list, new_gw);
}

void pingu_route_del(struct list_head *route_list,
			     struct pingu_route *delete)
{
	struct pingu_route *gw = pingu_route_get(route_list, delete);
	if (gw == NULL)
		return;
	log_debug_gw("removed", gw);
	list_del(&gw->route_list_entry);
	free(gw);
}

int is_default_gw(struct pingu_route *route)
{
	switch (route->dest.sa.sa_family) {
	case AF_INET:
		return (route->dest.sin.sin_addr.s_addr == 0);
		break;
	case AF_INET6:
		log_debug("TODO: ipv6");
		break;
	}
	return 0;
}
		
struct pingu_route *pingu_route_first_default(struct list_head *route_list)
{
	struct pingu_route *entry;
	list_for_each_entry(entry, route_list, route_list_entry) {
		if (is_default_gw(entry))
			return entry;
	}
	return NULL;
}

void pingu_route_dump(int fd, struct list_head *route_list)
{
	struct pingu_route *entry;
	list_for_each_entry(entry, route_list, route_list_entry) {
		char str[512] = "";
		pingu_route_to_string(entry, str, sizeof(str));
		if (str[0] != '\0') {
			strncat(str, "\n", sizeof(str));
			write(fd, str, strlen(str));
		}
	}
}

void pingu_route_cleanup(struct list_head *route_list)
{
	struct pingu_route *entry, *n;
	list_for_each_entry_safe(entry, n, route_list, route_list_entry) {
		list_del(&entry->route_list_entry);
		free(entry);
	}
}
