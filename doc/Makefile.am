SUBDIRS = \
	  examples \
	  manuals \
	  $(NULL)

HTML = \
       $(top_builddir)/doc/e1d/html/index.html \
       $(NULL)

if HAVE_DOXYGEN
html_DATA = $(top_builddir)/doc/html.tar

doc: $(html_DATA)

$(html_DATA): apidoc

.PHONY: apidoc
apidoc: $(HTML)
	cd $(top_builddir)/doc && tar cf html.tar */html

$(top_builddir)/doc/e1d/html/index.html:
	rm -rf $(top_builddir)/doc/e1d; mkdir -p $(top_builddir)/doc/e1d
	cd $(top_builddir) && $(DOXYGEN) Doxyfile

install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	cd $(DESTDIR)$(htmldir) && rm -rf e1d

DX_CLEAN = e1d/{html,latex}/* html.tar e1d/doxygen_sqlite3.db
endif

MOSTLYCLEANFILES = $(DX_CLEAN)
