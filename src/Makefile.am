include $(top_srcdir)/common.am

bin_PROGRAMS = nicetunnel
nicetunnel_SOURCES = main.c msanmissing.c journaldfix.c

if NICETUNNEL_WIN32
nicetunnel_SOURCES += resources.rc
endif

EXTRA_DIST = nicetunnel.ico

nicetunnel_LDADD = \
	libnicetunnel.a \
	$(NICETUNNELCOMMON_LIBS) \
	$(MY_NULL)

noinst_LIBRARIES = libnicetunnel.a

libnicetunnel_a_SOURCES = \
	nicetunnel.h \
	nicetunnel.c

mostlyclean-local:
	rm -f libnicetunnel.a
