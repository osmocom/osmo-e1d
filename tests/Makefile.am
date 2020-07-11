AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall -Wno-unused-result $(LIBOSMOCORE_CFLAGS)
LDADD = $(LIBOSMOCORE_LIBS) ../src/libosmo-e1d.la

bin_PROGRAMS = \
	raw_test \
	$(NULL)

raw_test_SOURCES = \
	raw_test.c \
	$(NULL)
