# WARP SNI Patcher (Linux) -- build
#
#   make            build ./warp-sni-patcher
#   make clean      remove build artifacts
#
# Needs a C compiler and glibc headers (<elf.h>, memmem). No external deps.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS ?=

BIN     := warp-sni-patcher
SRC     := main.c patcher.c i18n.c
OBJ     := $(SRC:.c=.o)
DEPS    := patcher.h i18n.h

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BIN) $(OBJ)
