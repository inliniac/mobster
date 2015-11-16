# ---------------------------------------------------------
# Make file for building mobster on raspberry pi 2 HW
# --------------------------------------------------------- 

# --------------------------------------------------------- 
# apt-get install libevent-dev redis-server libhiredis-dev
#         liblua5.1-0 liblua5.1-0-dev luajit libluajit-5.1-dev
# --------------------------------------------------------- 

# Clone JSMN from https://github.com/zserge/jsmn
# then point the following to the directory
JSMN_DIR=../../jsmn

CC=gcc
CFLAGS=-c -Wall -Werror -I$(JSMN_DIR) -DENABLE_JIT 
LDFLAGS=-lpthread -levent -lhiredis -lluajit-5.1 -llua5.1 
SOURCES=$(JSMN_DIR)/jsmn.c event_publisher.c event_handlers.c mobster.c 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=mobster

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm mobster mobster.o event_handlers.o event_publisher.o

