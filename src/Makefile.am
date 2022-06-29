SUBDIRS = octoi .

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=2:0:1

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wno-unused-result $(LIBOSMOCORE_CFLAGS) \
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
	ice1usb_proto.h \
	log.h \
	usb.h \
	e1gen/crc4itu.h \
	e1gen/osmo_e1f.h \
	$(NULL)


bin_PROGRAMS = \
	osmo-e1d \
	osmo-e1d-pipe \
	$(NULL)

noinst_PROGRAMS = \
	osmo-e1gen \
	$(NULL)

osmo_e1d_SOURCES = \
	ctl.c \
	intf_line.c \
	log.c \
	mux_demux.c \
	osmo-e1d.c \
	usb.c \
	vpair.c \
	vty.c \
	e1oip.c \
	$(NULL)

osmo_e1d_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) \
		 $(LIBOSMOUSB_LIBS) $(LIBUSB_LIBS) libosmo-e1d.la \
		 octoi/libosmo-octoi.la

osmo_e1d_pipe_SOURCES = \
	e1d-ts-pipe.c \
	$(NULL)

osmo_e1d_pipe_LDADD = $(LIBOSMOCORE_LIBS) libosmo-e1d.la


osmo_e1gen_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) \
		   $(LIBOSMOUSB_LIBS) $(LIBUSB_LIBS) \
		   octoi/libosmo-octoi.la

osmo_e1gen_SOURCES = \
	intf_line.c \
	log.c \
	e1gen/crc4itu.c \
	e1gen/osmo_e1f.c \
	osmo-e1gen.c \
	usb.c \
	vty.c \
	$(NULL)
