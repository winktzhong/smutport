#
# smutport makefile
#

OUTPUT = smutport
ifneq "$(wildcard ../lil)" ""
	LIL_PATH ?= ../lil
endif
ifneq "$(wildcard ../../lil)" ""
	LIL_PATH ?= ../../lil
endif
PREFIX ?= /usr/local
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))
HEADERS = $(wildcard *.h)
CFLAGS = -g3 -ansi -Wall -Wextra -Wno-unused-parameter
LDFLAGS = -L$(LIL_PATH) -llil
CFLAGS_FINAL = -I$(LIL_PATH) $(CFLAGS)

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	$(CC) -o $(OUTPUT) $(OBJECTS) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) -o $@ $(CFLAGS_FINAL) -c $<
	
.PHONY: install
install:
	mkdir -p $(PREFIX)/bin
	cp  $(OUTPUT) $(PREFIX)/bin/$(OUTPUT)
	
.PHONY: uninstall
uninstall:
	$(RM) $(PREFIX)/bin/$(OUTPUT)

.PHONY: clean
clean:
	$(RM) $(OUTPUT) $(OBJECTS)
	$(RM) -r output

.PHONY: distclean
distclean: clean
