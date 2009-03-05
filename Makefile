
TARGETS = mtu pingu
VERSION = 0.3

CFLAGS ?= -g
CFLAGS += -DPINGU_VERSION=\"$(VERSION)\"

prefix = /usr
BINDIR = $(prefix)/bin
DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d

pingu_OBJS = \
	icmp.o \
	log.o \
	pingu.o \
	xlib.o

mtu_OBJS = \
	mtu.o \
	netlink.o \
	icmp.o

ALL_OBJS= $(pingu_OBJS) $(mtu_OBJS)

all: $(TARGETS)

pingu: $(pingu_OBJS)

mtu: $(mtu_OBJS)

install: $(TARGETS)
	$(INSTALLDIR) $(DESTDIR)/$(BINDIR)
	$(INSTALL) $(TARGETS) $(DESTDIR)/$(BINDIR)
	
clean:
	rm -f $(TARGETS) $(ALL_OBJS)
