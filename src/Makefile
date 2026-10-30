# Makefile for aarch64 / arm64 targets
#
# Native build on an arm64 host: just run `make`.
# Cross-compiling from an x86_64 host: install an aarch64 toolchain
# (e.g. `aarch64-linux-gnu-gcc` on Debian/Ubuntu via
# `apt install gcc-aarch64-linux-gnu`) and run:
#   make CC=aarch64-linux-gnu-gcc

CC      := aarch64-linux-gnu-gcc
CFLAGS  := -Wall -Wextra -O2 -g -D_GNU_SOURCE -march=armv8-a
LDFLAGS := -lpthread
TARGET  := main
SRC     := main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)