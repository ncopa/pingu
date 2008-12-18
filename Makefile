
TARGETS = pingu mtu
CFLAGS ?= -g

pingu_OBJS = \
	log.o \
	pingu.o \
	xlib.o

mtu_OBJS = \
	mtu.o

ALL_OBJS= $(pingu_OBJS) $(mtu_OBJS)

all: $(TARGETS)

pingu: $(pingu_OBJS)

mtu: $(mtu_OBJS)

clean:
	rm -f $(TARGETS) $(ALL_OBJS)
