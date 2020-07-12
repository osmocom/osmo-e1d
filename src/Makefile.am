# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=0:0:0

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -Wno-unused-result $(LIBOSMOCORE_CFLAGS) \
	  $(LIBOSMOVTY_CFLAGS) $(LIBOSMOUSB_CFLAGS) $(LIBUSB_CFLAGS)

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
	frame_relay.h \
	$(NULL)


bin_PROGRAMS = \
	osmo-e1d \
	osmo-e1d-pipe \
	e1d-fr-test \
	$(NULL)

osmo_e1d_SOURCES = \
	ctl.c \
	intf_line.c \
	log.c \
	osmo-e1d.c \
	usb.c \
	vpair.c \
	vty.c \
	$(NULL)

osmo_e1d_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) \
		 $(LIBOSMOUSB_LIBS) $(LIBUSB_LIBS) libosmo-e1d.la

osmo_e1d_pipe_SOURCES = \
	e1d-ts-pipe.c \
	$(NULL)

osmo_e1d_pipe_LDADD = $(LIBOSMOCORE_LIBS) libosmo-e1d.la

e1d_fr_test_SOURCES = \
	e1d-fr-test.c \
	frame_relay.c \
	$(NULL)

e1d_fr_test_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) libosmo-e1d.la
