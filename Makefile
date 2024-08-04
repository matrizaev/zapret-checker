TARGET = zapret-checker
PREFIX ?= 
SRCS = zapret-checker.c zapret-soap.c zapret-smtp.c zapret-configuration.c zapret-process.c zapret-netfilter.c zapret-rawHTTP.c zapret-rawDNS.c zapret-cleaning.c util.c sign.c pfhash.c
CFG = zapret-checker.xml custom.xml
OBJS = $(SRCS:.c=.o)
CFLAGS_LOCAL = -g -O3 -Wall -Wextra -std=gnu99 `xml2-config --cflags` `curl-config --cflags` `pkg-config --cflags libzip`
LDFLAGS_LOCAL = -g -lnetfilter_queue `xml2-config --libs`  `curl-config --libs` `pkg-config --libs libzip` -ldl -lpthread -lidn2 -lm
CC = gcc

.PHONY: all clean install uninstall

all: $(TARGET)
$(TARGET): zapret-configuration.h $(OBJS)
	$(CC)  $(OBJS) $(LDFLAGS_LOCAL) -o $(TARGET)
	
zapret-configuration.h: zapret-configuration.h.include

zapret-configuration.h.include: zapret-checker.xsd
	cat zapret-checker.xsd | tr -d '\t\r\n' | xxd -i > zapret-configuration.h.include
	
%.o: %.c
	$(CC) -c $(CFLAGS_LOCAL) $< -o $@

clean:
	rm -rf $(TARGET) $(OBJS) zapret-configuration.h.include
install:
	install $(TARGET) $(PREFIX)/bin
#	mkdir -pv $(PREFIX)/bin/ $(PREFIX)/etc/$(TARGET)/
#	cp -vf $(CFG) $(PREFIX)/etc/$(TARGET)/
#	cp -vf ./$(TARGET).service /etc/systemd/system
uninstall:
	rm -rf $(PREFIX)/bin/$(TARGET)
	rm -rf /etc/systemd/system/$(TARGET).service
	rm -rf /etc/$(TARGET)/


rutoken-sign: rutoken-sign.c sign.c sign.h
	$(CC) rutoken-sign.c sign.c -ldl -o rutoken-sign
