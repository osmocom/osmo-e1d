AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = \
	contrib \
	doc \
	src \
	include \
	tests \
	$(NULL)

EXTRA_DIST = \
	.version \
	debian \
	doc \
	git-version-gen \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-e1d.pc libosmo-octoi.pc

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)


@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
