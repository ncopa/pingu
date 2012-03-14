#ifndef pingu_route_H
#define pingu_route_H

#include "list.h"
#include "sockaddr_util.h"

struct pingu_route {
	union sockaddr_any gw_addr;
	union sockaddr_any dest;
	union sockaddr_any src;
	unsigned char dst_len;
	unsigned char src_len;

	int metric;
	int dev_index;
	unsigned char protocol;
	unsigned char scope;
	unsigned char type;
	struct list_head route_list_entry;
};

char *pingu_route_to_string(struct pingu_route *route,
			    char *buf, size_t bufsize);
void pingu_route_del_all(struct list_head *head);
void pingu_route_add(struct list_head *route_list,
			     struct pingu_route *gw);
void pingu_route_del(struct list_head *route_list,
			     struct pingu_route *gw);
int is_default_gw(struct pingu_route *route);
struct pingu_route *pingu_route_first_default(struct list_head *route_list);
void pingu_route_cleanup(struct list_head *route_list);

#endif
