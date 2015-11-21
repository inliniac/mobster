noinst_HEADERS = \
event_handlers.h \
event_publisher.h

bin_PROGRAMS = mobster

mobster_SOURCES = \
event_handlers.c \
event_publisher.c \
mobster.c

# set the include path found by configure
AM_CPPFLAGS = $(all_includes)

# the library search path.
mobster_LDFLAGS = $(all_libraries)

