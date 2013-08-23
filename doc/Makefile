
MANDIR ?= /usr/share/man
MAN5PAGES = pingu.conf.5
MAN8PAGES = pingu.8 pinguctl.8
ALL_MANPAGES = $(MAN5PAGES) $(MAN8PAGES)
TXT_FILES = pingu.txt pingu.conf.txt pinguctl.txt

DEFAULT_ADM_SOCKET ?= /var/run/pingu/pingu.ctl
DEFAULT_PIDFILE ?= /var/run/pingu/pingu.pid
DEFAULT_CONFIG ?= /etc/pingu/pingu.conf

INSTALL := install
INSTALLDIR := $(INSTALL) -d
SED := sed

SED_REPLACE = -e 's:@DEFAULT_ADM_SOCKET@:$(DEFAULT_ADM_SOCKET):g' \
	-e 's:@DEFAULT_PIDFILE@:$(DEFAULT_PIDFILE):g' \
	-e 's:@DEFAULT_CONFIG@:$(DEFAULT_CONFIG):g'

replace	= $(SED) $(SED_REPLACE) $(SED_EXTRA) $< > $@

.SUFFIXES: .in
.in:
	$(replace)

%.5: %.txt
	a2x -f manpage $<

%.8: %.txt
	a2x -f manpage $<

all:	$(ALL_MANPAGES)

pingu.conf.5: pingu.conf.txt
pingu.8: pingu.txt
pinguctl.8: pinguctl.txt

clean:
	rm -f $(ALL_MANPAGES) $(TXT_FILES)

install: $(ALL_MANPAGES)
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) $(MAN5PAGES) $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) $(MAN8PAGES) $(DESTDIR)$(MANDIR)/man8
