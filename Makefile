
-include config.mk

BIN_TARGETS = mtu
SBIN_TARGETS = pingu pinguctl

TARGETS = $(BIN_TARGETS) $(SBIN_TARGETS) $(LUA_TARGETS)
PINGU_VERSION := $(shell \
	if [ -d .git ]; then \
		git describe --long; \
	else \
		echo $(PACKAGE_VERSION); \
	fi)

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
sbindir ?= $(exec_prefix)/sbin
sysconfdir ?= $(prefix)/etc
localstatedir ?= $(prefix)/var
libdir ?= $(exec_prefix)/lib
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man

rundir ?= $(localstatedir)/run

pingustatedir = $(rundir)/pingu

DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d
PKG_CONFIG ?= pkg-config

ifdef LUAPC
LUA_TARGETS := client.so
INSTALL_LUA_TARGET := install-lua
LUA_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(LUAPC))
LUA_VERSION ?= $(shell $(PKG_CONFIG) --variable V $(LUAPC))

luasharedir := $(datarootdir)/lua/$(LUA_VERSION)
lualibdir := $(libdir)/lua/$(LUA_VERSION)

endif

SUBDIRS := man

CFLAGS ?= -g
CFLAGS += -DPINGU_VERSION=\"$(PINGU_VERSION)\"
CFLAGS += -Wall -Wstrict-prototypes -D_GNU_SOURCE -std=gnu99
CFLAGS += -DDEFAULT_PIDFILE=\"$(pingustatedir)/pingu.pid\"
CFLAGS += -DDEFAULT_CONFIG=\"$(sysconfdir)/pingu/pingu.conf\"
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

lua-client.o_CFLAGS = $(LUA_CFLAGS)
client.so_OBJS = \
	lua-client.o

client.so_LDFLAGS = -shared

ALL_OBJS= $(pingu_OBJS) $(pinguctl_OBJS) $(mtu_OBJS) $(client.so_OBJS)

all: $(TARGETS) man

%.o: %.c
	$(CC) $(CFLAGS) $($@_CFLAGS) -c $<

$(TARGETS):
	$(CC) $(LDFLAGS) $($@_LDFLAGS) $($@_OBJS) $($@_LIBS) -o $@

pingu: $(pingu_OBJS)
pinguctl: $(pinguctl_OBJS)
client.so: $(client.so_OBJS)
mtu: $(mtu_OBJS)

$(SUBDIRS):
	$(MAKE) -C $@

install: $(TARGETS) $(INSTALL_LUA_TARGET)
	$(INSTALLDIR) $(DESTDIR)/$(bindir) $(DESTDIR)/$(sbindir) \
		$(DESTDIR)/$(pingustatedir)
	$(INSTALL) $(BIN_TARGETS) $(DESTDIR)/$(bindir)
	$(INSTALL) $(SBIN_TARGETS) $(DESTDIR)/$(sbindir)
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
