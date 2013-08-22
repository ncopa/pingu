#ifndef PINGU_BURST_H
#define PINGU_BURST_H

#include <sys/types.h>
#include <sys/socket.h>

#include <ev.h>

#include "list.h"
#include "sockaddr_util.h"

struct pingu_burst {
	union sockaddr_any saddr;
//	size_t saddrlen;
	int pings_sent;
	int pings_replied;
	int active;
	struct list_head ping_burst_entry;
};

void pingu_burst_timeout_cb(struct ev_loop *loop, struct ev_timer *w,
			    int revents);

#endif
