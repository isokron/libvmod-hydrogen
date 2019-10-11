AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_hydrogen.la

libvmod_hydrogen_la_SOURCES = \
	vmod_hydrogen.c \
	libhydrogen/hydrogen.c \
	libhydrogen/hydrogen.h \
	base64.c \
	base64.h

nodist_libvmod_hydrogen_la_SOURCES = \
	vcc_hydrogen_if.c \
	vcc_hydrogen_if.h

dist_man_MANS = vmod_hydrogen.3

@BUILD_VMOD_HYDROGEN@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_hydrogen="$(VMOD_HYDROGEN)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_hydrogen.vcc \
	$(VMOD_TESTS)
