#ifndef PINGU_GATEWAY_H
#define PINGU_GATEWAY_H

#include "list.h"
#include "sockaddr_util.h"

struct pingu_gateway {
	union sockaddr_any gw_addr;
	union sockaddr_any dest;
	union sockaddr_any src;
	unsigned char dst_len;
	unsigned char src_len;
	
	int metric;
	unsigned char protocol;
	unsigned char scope;
	unsigned char type;	
	struct list_head gateway_list_entry;
};

void pingu_gateway_del_all(struct list_head *head);
void pingu_gateway_add(struct list_head *gateway_list,
			     struct pingu_gateway *gw);
void pingu_gateway_del(struct list_head *gateway_list,
			     struct pingu_gateway *gw);
			     


#endif
