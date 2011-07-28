#include <sys/socket.h>
#include <sys/types.h>

#include <netdb.h>
#include <string.h>

#include <ev.h>

#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_ping.h"
#include "pingu_iface.h"

void ping_burst_start(struct ev_loop *loop, struct pingu_host *host)
{
	struct addrinfo hints;
	struct addrinfo *ai, *rp;
	int r;

	/* we bind to device every burst in case an iface disappears and
	   comes back. e.g ppp0 */
	if (pingu_iface_bind_socket(host->iface, host->status) < 0) {
		pingu_host_set_status(host, 0);
		return;
	}
	
	host->burst.active = 1;
	host->burst.pings_sent = 0;
	host->burst.pings_replied = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	r = getaddrinfo(host->host, NULL, &hints, &ai);
	if (r < 0) {
		log_error("getaddrinfo(%s): %s", host->host, gai_strerror(r));
		return;
	}

	for (rp = ai; rp != NULL; rp = rp->ai_next) {
		sockaddr_init(&host->burst.saddr, ai->ai_family,
			     ai->ai_addr);
		r = pingu_ping_send(loop, host, 0);
		if (r == 0)
			break;
	}

	if (rp == NULL)
		host->burst.active = 0;
	
}

void pingu_burst_timeout_cb(struct ev_loop *loop, struct ev_timer *w,
                            int revents)
{
	struct pingu_host *host = container_of(w, struct pingu_host, burst_timeout_watcher);

	if (host->burst.active) {
		log_warning("%s: burst already active", host->host);
		return;
	}
	log_debug("%s: new burst", host->host);
	ping_burst_start(loop, host);
}
