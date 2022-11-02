EXTRA_DIST = \
    osmoe1d-usermanual.adoc \
    osmoe1d-usermanual-docinfo.xml \
    chapters \
    $(NULL)

if BUILD_MANUALS
  ASCIIDOC = osmoe1d-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  OSMO_REPOSITORY = osmo-e1d
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
