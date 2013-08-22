
-include ../../config.mk

TARGETS = client.so

prefix ?= /usr/local
exec_prefix ?= $(prefix)
localstatedir ?= $(prefix)/var
libdir ?= $(exec_prefix)/lib
datarootdir ?= $(prefix)/share

rundir ?= $(localstatedir)/run
pingustatedir = $(rundir)/pingu

DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d
PKG_CONFIG ?= pkg-config

LUA_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(LUAPC))
LUA_VERSION ?= $(shell $(PKG_CONFIG) --variable V $(LUAPC))

luasharedir := $(datarootdir)/lua/$(LUA_VERSION)
lualibdir := $(libdir)/lua/$(LUA_VERSION)

SUBDIRS :=

CFLAGS ?= -g
CFLAGS += -I../../ -I..
CFLAGS += -DPINGU_VERSION=\"$(PINGU_VERSION)\"
CFLAGS += -Wall -Wstrict-prototypes -D_GNU_SOURCE -std=gnu99
CFLAGS += -DDEFAULT_ADM_client=\"$(pingustatedir)/pingu.ctl\"


lua-client.o_CFLAGS = $(LUA_CFLAGS)
client.so_OBJS = \
	lua-client.o

client.so_LDFLAGS = -shared

ALL_OBJS= $(client.so_OBJS)

all: $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) $($@_CFLAGS) -c $<

$(TARGETS):
	$(CC) $(LDFLAGS) $($@_LDFLAGS) $($@_OBJS) $($@_LIBS) -o $@

client.so: $(client.so_OBJS)

install: client.so pingu.lua
	$(INSTALLDIR) $(DESTDIR)$(luasharedir) \
		$(DESTDIR)$(lualibdir)/pingu
	$(INSTALL) pingu.lua $(DESTDIR)$(luasharedir)/
	$(INSTALL) client.so $(DESTDIR)$(lualibdir)/pingu/

clean:
	rm -f $(TARGETS) $(ALL_OBJS)

.PHONY: clean all install
