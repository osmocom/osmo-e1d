AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = \
	src \
	include \
	$(NULL)

EXTRA_DIST = \
	.version \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-e1d.pc

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
