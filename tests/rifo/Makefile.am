AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/octoi \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	rifo_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	rifo_test \
	$(NULL)

rifo_test_SOURCES = \
	rifo_test.c \
	$(NULL)

rifo_test_LDADD = \
	$(top_builddir)/src/octoi/frame_rifo.o \
	$(top_builddir)/src/log.o \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
