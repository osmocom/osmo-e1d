# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=0:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBUSB_CFLAGS)

lib_LTLIBRARIES = libosmo-e1d.la

libosmo_e1d_la_SOURCES = \
	proto.c \
	proto_clnt.c \
	proto_srv.c \
	$(NULL)

libosmo_e1d_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
libosmo_e1d_la_LIBADD = $(LIBOSMOCORE_LIBS)


noinst_HEADERS = \
	e1d.h \
	log.h \
	$(NULL)


bin_PROGRAMS = \
	osmo-e1d \
	$(NULL)

osmo_e1d_SOURCES = \
	ctl.c \
	log.c \
	osmo-e1d.c \
	usb.c \
	$(NULL)

osmo_e1d_LDADD = $(LIBOSMOCORE_LIBS) $(LIBUSB_LIBS) libosmo-e1d.la
