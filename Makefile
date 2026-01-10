CC = gcc
CFLAGS = -Wall -Wextra -I./src
LDFLAGS = -lcjson -lreadline
RELEASE_FLAGS = -Os
DEBUG_FLAGS = -g -O0
TARGET = vpner
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

all: release
release: CFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

$(TARGET): src/vpner.c src/tui_main.c src/config_load.c src/urlconfig/tui_urlconfig.c src/urlconfig/proto_parsr.c src/urlconfig/proto_serlz.c src/urlconfig/urlconfig.h src/urlconfig/bean.c src/urlconfig/doh.h src/help.h src/utils.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: release
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all release debug install uninstall clean
