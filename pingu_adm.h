#ifndef PINGU_ADM_H
#define PINGU_ADM_H

#include <ev.h>

#ifndef DEFAULT_ADM_SOCKET
#define DEFAULT_ADM_SOCKET "/var/run/pingu/pingu.ctl"
#endif

int pingu_adm_init(struct ev_loop *loop, const char *socket_path);

#endif
