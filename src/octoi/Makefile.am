AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wno-unused-result $(LIBOSMOCORE_CFLAGS) \
	  $(LIBOSMOVTY_CFLAGS)

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=1:0:0

lib_LTLIBRARIES = libosmo-octoi.la

libosmo_octoi_la_SOURCES = \
	frame_fifo.c \
	frame_rifo.c \
	e1oip.c \
	octoi.c \
	octoi_sock.c \
	octoi_fsm.c \
	octoi_srv_fsm.c \
	octoi_srv_vty.c \
	octoi_clnt_fsm.c \
	octoi_clnt_vty.c \
	$(NULL)

libosmo_octoi_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined \
			   -Wl,--version-script=$(srcdir)/libosmo-octoi.map
libosmo_octoi_la_LIBADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)

noinst_HEADERS = \
	e1oip.h \
	frame_fifo.h \
	frame_rifo.h \
	octoi.h \
	octoi_fsm.h \
	octoi_sock.h \
	octoi_vty.h \
	$(NULL)

EXTRA_DIST = libosmo-octoi.map
