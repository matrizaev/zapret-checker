TARGET = zapret-checker
DOWNLOAD_TARGET = zapret-download
PREFIX ?=
SRCS = zapret-checker.c zapret-soap.c zapret-smtp.c zapret-configuration.c zapret-process.c zapret-netfilter.c zapret-rawHTTP.c zapret-rawDNS.c zapret-cleaning.c util.c sign.c pfhash.c
CFG = zapret-checker.xml custom.xml
OBJS = $(SRCS:.c=.o)
DOWNLOAD_OBJS = zapret-download.o zapret-soap.o zapret-smtp.o util.o sign.o
CFLAGS_LOCAL = -g -O3 -Wall -Wextra -std=gnu99 `xml2-config --cflags` `curl-config --cflags` `pkg-config --cflags libzip`
LDFLAGS_LOCAL = -g -lnetfilter_queue `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lpthread -lidn2 -lm
DOWNLOAD_LDFLAGS = `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lidn2
CC = gcc

.PHONY: all clean install uninstall

all: $(TARGET) $(DOWNLOAD_TARGET)

$(TARGET): zapret-configuration.h $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS_LOCAL) -o $(TARGET)

$(DOWNLOAD_TARGET): $(DOWNLOAD_OBJS)
	$(CC) $(DOWNLOAD_OBJS) $(DOWNLOAD_LDFLAGS) -o $(DOWNLOAD_TARGET)

zapret-configuration.h: zapret-configuration.h.include

zapret-configuration.h.include: zapret-checker.xsd
	cat zapret-checker.xsd | tr -d '\t\r\n' | xxd -i > zapret-configuration.h.include

%.o: %.c
	$(CC) -c $(CFLAGS_LOCAL) $< -o $@

clean:
	rm -rf $(TARGET) $(DOWNLOAD_TARGET) $(OBJS) zapret-download.o zapret-configuration.h.include

install:
	install $(TARGET) $(DOWNLOAD_TARGET) $(PREFIX)/bin
#	mkdir -pv $(PREFIX)/bin/ $(PREFIX)/etc/$(TARGET)/
#	cp -vf $(CFG) $(PREFIX)/etc/$(TARGET)/
#	cp -vf ./$(TARGET).service /etc/systemd/system

uninstall:
	rm -rf $(PREFIX)/bin/$(TARGET)
	rm -rf $(PREFIX)/bin/$(DOWNLOAD_TARGET)
	rm -rf /etc/systemd/system/$(TARGET).service
	rm -rf /etc/$(TARGET)/

rutoken-sign: rutoken-sign.c sign.c sign.h
	$(CC) rutoken-sign.c sign.c -ldl -o rutoken-sign
