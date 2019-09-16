mod_opentracing.la: mod_opentracing.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_opentracing.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_opentracing.la
