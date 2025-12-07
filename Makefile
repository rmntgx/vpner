CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcjson -lreadline
RELEASE_FLAGS = -Os
DEBUG_FLAGS = -g
TARGET = vpner
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

all: release
release: $(TARGET)
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

$(TARGET): src/vpner.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(RELEASE_FLAGS)

install: release
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all release debug install uninstall clean
