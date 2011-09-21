
TARGETS = mtu pingu pinguctl
VERSION = 0.5

prefix = /usr
localstatedir = /var
rundir = $(localstatedir)/run
pingustatedir = $(rundir)/pingu

BINDIR = $(prefix)/bin
DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d

CFLAGS ?= -g
CFLAGS += -DPINGU_VERSION=\"$(VERSION)\"
CFLAGS += -Wall -Wstrict-prototypes -D_GNU_SOURCE -std=gnu99
CFLAGS += -DDEFAULT_PIDFILE=\"$(pingustatedir)/pingu.pid\"
CFLAGS += -DDEFAULT_ADM_SOCKET=\"$(pingustatedir)/pingu.ctl\"

pingu_OBJS = \
	icmp.o \
	log.o \
	pingu.o \
	pingu_adm.o \
	pingu_burst.o \
	pingu_conf.o \
	pingu_gateway.o \
	pingu_host.o \
	pingu_iface.o \
	pingu_netlink.o \
	pingu_ping.o \
	sockaddr_util.o \
	xlib.o

pingu_LIBS = -lev

pinguctl_OBJS = \
	log.o \
	pinguctl.o

pinguctl_LIBS =

mtu_OBJS = \
	mtu.o \
	netlink.o \
	icmp.o

ALL_OBJS= $(pingu_OBJS) $(pinguctl_OBJS) $(mtu_OBJS)

all: $(TARGETS)

pingu: $(pingu_OBJS)
	$(CC) $(LDFLAGS) $(pingu_OBJS) $(pingu_LIBS) -o $@

pinguctl: $(pinguctl_OBJS)
	$(CC) $(LDFLAGS) $(pinguctl_OBJS) $(pinguctl_LIBS) -o $@

mtu: $(mtu_OBJS)

install: $(TARGETS)
	$(INSTALLDIR) $(DESTDIR)/$(BINDIR) $(DESTDIR)/$(pingustatedir)
	$(INSTALL) $(TARGETS) $(DESTDIR)/$(BINDIR)

clean:
	rm -f $(TARGETS) $(ALL_OBJS)
