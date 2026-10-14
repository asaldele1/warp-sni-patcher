# WARP SNI Patcher (Linux) -- build
#
#   make              build ./warp-sni-patcher (dynamically linked)
#   make STATIC=1     build a fully static binary (no libc version dependency;
#                     runs on any x86-64 Linux, e.g. glibc 2.33+). Used by CI
#                     so release binaries are portable across distros.
#   make clean        remove build artifacts
#
# Needs a C compiler and glibc headers (<elf.h>, memmem). No external deps.
# STATIC=1 additionally needs the static libc archive (glibc-static /
# libc6-dev with libc.a).

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS ?=

ifeq ($(STATIC),1)
  LDFLAGS += -static
endif

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
