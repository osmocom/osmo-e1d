osmocom/%/version.h: osmocom/%/version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

nobase_include_HEADERS = \
	osmocom/e1d/proto.h \
	osmocom/e1d/proto_clnt.h \
	osmocom/e1d/proto_srv.h \
	osmocom/e1d/version.h \
	osmocom/octoi/e1oip_proto.h \
	osmocom/octoi/octoi.h \
	osmocom/octoi/version.h \
	$(NULL)
