
TARGETS = pingu mtu
CFLAGS ?= -g

pingu_OBJS = \
	pingu.o \
	log.o

mtu_OBJS = \
	mtu.o

ALL_OBJS= $(pingu_OBJS) $(mtu_OBJS)

all: $(TARGETS)

pingu: $(pingu_OBJS)

mtu: $(mtu_OBJS)

clean:
	rm -f $(TARGETS) $(ALL_OBJS)
