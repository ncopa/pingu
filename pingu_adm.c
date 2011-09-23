
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "list.h"
#include "log.h"
#include "pingu_adm.h"
#include "pingu_host.h"

static struct ev_io accept_io;

struct adm_conn {
        struct ev_io io;
        struct ev_timer timeout;
        int num_read;
        char cmd[512];
};

static void pingu_adm_free_conn(struct ev_loop *loop, struct adm_conn *rm)
{
        int fd = rm->io.fd;

        ev_io_stop(loop, &rm->io);
        ev_timer_stop(loop, &rm->timeout);
        close(fd);
        free(rm);
}

static void pingu_adm_recv_cb (struct ev_loop *loop, struct ev_io *w,
			       int revents)
{
	struct adm_conn *conn = container_of(w, struct adm_conn, io);
	int len;

	len = recv(conn->io.fd, conn->cmd, sizeof(conn->cmd) - conn->num_read,
		   MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return;
	if (len <= 0)
		goto err;

	conn->num_read += len;
	if (conn->num_read >= sizeof(conn->cmd))
		goto err;
	if (conn->cmd[conn->num_read - 1] != '\n')
		goto err;

	conn->num_read--;
	conn->cmd[conn->num_read] = '\0';

	if (strncmp(conn->cmd, "status", len) == 0) {
		log_debug("Admin command: %s", conn->cmd);
		pingu_host_dump_status(conn->io.fd);
		conn->cmd[0] = '\0';
		conn->num_read = 0;
	} else {
		log_error("unknown adm command");
	}
	return;

err:
	pingu_adm_free_conn(loop, conn);
}

static void pingu_adm_timeout_cb (struct ev_loop *loop, struct ev_timer *t,
				  int revents)
{
	log_debug("Admin connection timed out");
	pingu_adm_free_conn(loop, container_of(t, struct adm_conn, timeout));
}

static void pingu_adm_accept_cb(struct ev_loop *loop, struct ev_io *w,
				int revents)
{
	struct adm_conn *conn;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	int fd;

	fd = accept(w->fd, (struct sockaddr *) &from, &fromlen);
	if (fd < 0) {
		log_perror("accept");
		return;
	}
	log_debug("New admin connection");
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	conn = calloc(1, sizeof(struct adm_conn));

	ev_io_init(&conn->io, pingu_adm_recv_cb, fd, EV_READ);
	ev_io_start(loop, &conn->io);
        ev_timer_init(&conn->timeout, pingu_adm_timeout_cb, 10.0, 0.);
        ev_timer_start(loop, &conn->timeout);
}


int pingu_adm_init(struct ev_loop *loop, const char *socket_path)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_perror("socket");
		return -1;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	unlink(socket_path);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0)
		goto perr_close;

	if (listen(fd, 5) < 0)
		goto perr_close;

	ev_io_init(&accept_io, pingu_adm_accept_cb, fd, EV_READ);
	ev_io_start(loop, &accept_io);
	return 0;

perr_close:
	log_perror(socket_path);
	close(fd);
	return -1;

}
