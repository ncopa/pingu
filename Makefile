
-include config.mk

PINGU_VERSION := $(shell \
	if [ -d .git ]; then \
		git describe --long; \
	else \
		echo $(PACKAGE_VERSION); \
	fi)

export PINGU_VERSION

SUBDIRS := src doc

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

install clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@ || break; \
	done

.PHONY: $(SUBDIRS) all install clean
