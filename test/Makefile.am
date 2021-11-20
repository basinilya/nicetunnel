include $(top_srcdir)/common.am

AM_TESTS_ENVIRONMENT =

TESTS = \
	$(FILE_BASED_TESTS) \
	$(MY_NULL)

TEST_EXTENSIONS = .txt

## 
TXT_LOG_COMPILER = $(SHELL) $(srcdir)/wrapper-script

FILE_BASED_TESTS = \
	$(MY_NULL)

EXTRA_DIST = wrapper-script $(FILE_BASED_TESTS) $(FILE_BASED_TESTS:=.exp.txt)

CLEANFILES += *.log
