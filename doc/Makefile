
MANDIR ?= /usr/share/man
MAN5PAGES = pingu.conf.5
MAN8PAGES = pingu.8 pinguctl.8
ALL_MANPAGES = $(MAN5PAGES) $(MAN8PAGES)

DEFAULT_ADM_SOCKET ?= /var/run/pingu/pingu.ctl
DEFAULT_PIDFILE ?= /var/run/pingu/pingu.pid
DEFAULT_CONFIG ?= /etc/pingu/pingu.conf

INSTALL := install
INSTALLDIR := $(INSTALL) -d
SED := sed

SED_REPLACE = -e 's:@DEFAULT_ADM_SOCKET@:$(DEFAULT_ADM_SOCKET):g' \
	-e 's:@DEFAULT_PIDFILE@:$(DEFAULT_PIDFILE):g' \
	-e 's:@DEFAULT_CONFIG@:$(DEFAULT_CONFIG):g'

mkman	= $(SED) $(SED_REPLACE) $(SED_EXTRA) $< > $@

.SUFFIXES: .in
.in:
	$(mkman)

all:	$(ALL_MANPAGES)

clean:
	rm -f $(ALL_MANPAGES)

install: $(ALL_MANPAGES)
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) $(MAN5PAGES) $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) $(MAN8PAGES) $(DESTDIR)$(MANDIR)/man8
