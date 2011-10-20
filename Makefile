
TARGETS = mtu pingu pinguctl client.so
VERSION = 0.5

prefix = /usr
localstatedir = /var
rundir = $(localstatedir)/run
pingustatedir = $(rundir)/pingu

luasharedir = /usr/share/lua/5.1
lualibdir = /usr/lib/lua/5.1

SBINDIR = $(prefix)/sbin
DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d
PKG_CONFIG ?= pkg-config

SUBDIRS := man

CFLAGS ?= -g
CFLAGS += -DPINGU_VERSION=\"$(VERSION)\"
CFLAGS += -Wall -Wstrict-prototypes -D_GNU_SOURCE -std=gnu99
CFLAGS += -DDEFAULT_PIDFILE=\"$(pingustatedir)/pingu.pid\"
CFLAGS += -DDEFAULT_ADM_client=\"$(pingustatedir)/pingu.ctl\"

pingu_OBJS = \
	icmp.o \
	log.o \
	pingu.o \
	pingu_adm.o \
	pingu_burst.o \
	pingu_conf.o \
	pingu_host.o \
	pingu_iface.o \
	pingu_netlink.o \
	pingu_ping.o \
	pingu_route.o \
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

client.so_OBJS = \
	lua-client.o

client.so_LIBS = $(shell $(PKG_CONFIG) --libs lua)
client.so_LDFLAGS = -shared

ALL_OBJS= $(pingu_OBJS) $(pinguctl_OBJS) $(mtu_OBJS) $(client.so_OBJS)

all: $(TARGETS) man

$(TARGETS):
	$(CC) $(LDFLAGS) $($@_LDFLAGS) $($@_OBJS) $($@_LIBS) -o $@

pingu: $(pingu_OBJS)
pinguctl: $(pinguctl_OBJS)
client.so: $(client.so_OBJS)
mtu: $(mtu_OBJS)

$(SUBDIRS):
	$(MAKE) -C $@

install: $(TARGETS)
	$(INSTALLDIR) $(DESTDIR)/$(SBINDIR) $(DESTDIR)/$(pingustatedir)
	$(INSTALL) $(TARGETS) $(DESTDIR)/$(SBINDIR)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@ || break; \
	done

install-lua: client.so pingu.lua
	$(INSTALLDIR) $(DESTDIR)$(luasharedir) \
		$(DESTDIR)$(lualibdir)/pingu
	$(INSTALL) pingu.lua $(DESTDIR)$(luasharedir)/
	$(INSTALL) client.so $(DESTDIR)$(lualibdir)/pingu/

clean:
	rm -f $(TARGETS) $(ALL_OBJS)
	$(MAKE) -C man clean

.PHONY: $(SUBDIRS)
