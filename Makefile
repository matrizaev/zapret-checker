TARGET = zapret-checker
DOWNLOAD_TARGET = zapret-download
SIGN_TARGET = rutoken-sign
TEST_TARGET = tests/test_core
SOAP_TEST_TARGET = tests/test_soap
SOAP_INTERACTION_TEST_TARGET = tests/test_soap_interaction
REGISTER_TEST_TARGET = tests/test_register
TEST_SANITIZER_TARGET = tests/test_core-sanitize
SOAP_TEST_SANITIZER_TARGET = tests/test_soap-sanitize
SOAP_INTERACTION_TEST_SANITIZER_TARGET = tests/test_soap_interaction-sanitize
REGISTER_TEST_SANITIZER_TARGET = tests/test_register-sanitize
SOAP_TEST_FIXTURES = tests/fixtures/soap/README.md $(wildcard tests/fixtures/soap/*.xml)
REGISTER_TEST_FIXTURES = tests/fixtures/register/README.md $(wildcard tests/fixtures/register/*.xml) tests/fixtures/register/blacklist.zip.base64
PREFIX ?=
SRCS = zapret-checker.c zapret-soap.c zapret-smtp.c zapret-configuration.c zapret-process.c zapret-netfilter.c zapret-rawHTTP.c zapret-rawDNS.c zapret-cleaning.c util.c sign.c pfhash.c
CFG = zapret-checker.xml custom.xml
OBJS = $(SRCS:.c=.o)
DOWNLOAD_OBJS = zapret-download.o zapret-soap.o zapret-smtp.o util.o sign.o
CFLAGS_LOCAL = -g -O3 -Wall -Wextra -std=gnu99 `xml2-config --cflags` `curl-config --cflags` `pkg-config --cflags libzip`
LDFLAGS_LOCAL = -g -lnetfilter_queue `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lpthread -lidn2 -lm
DOWNLOAD_LDFLAGS = `xml2-config --libs` `curl-config --libs` `pkg-config --libs libzip` -ldl -lidn2
TEST_CFLAGS = -g -O0 -Wall -Wextra -std=gnu99 -I. `xml2-config --cflags` `curl-config --cflags`
TEST_LDFLAGS = `xml2-config --libs` `curl-config --libs`
SANITIZER_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
CC = gcc

.PHONY: all test test-sanitize clean install uninstall

all: $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET)

$(TARGET): zapret-configuration.h $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS_LOCAL) -o $(TARGET)

$(DOWNLOAD_TARGET): $(DOWNLOAD_OBJS)
	$(CC) $(DOWNLOAD_OBJS) $(DOWNLOAD_LDFLAGS) -o $(DOWNLOAD_TARGET)

zapret-configuration.h: zapret-configuration.h.include

zapret-configuration.h.include: zapret-checker.xsd
	cat zapret-checker.xsd | tr -d '\t\r\n' | xxd -i > zapret-configuration.h.include

%.o: %.c
	$(CC) -c $(CFLAGS_LOCAL) $< -o $@

test: $(TEST_TARGET) $(SOAP_TEST_TARGET) $(SOAP_INTERACTION_TEST_TARGET) $(REGISTER_TEST_TARGET)
	./$(TEST_TARGET)
	./$(SOAP_TEST_TARGET)
	./$(SOAP_INTERACTION_TEST_TARGET)
	./$(REGISTER_TEST_TARGET)

$(TEST_TARGET): tests/test_core.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_core.c tests/vendor/munit/munit.c util.c pfhash.c $(TEST_LDFLAGS) -o $(TEST_TARGET)

$(SOAP_TEST_TARGET): tests/test_soap.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_soap.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -o $(SOAP_TEST_TARGET)

$(SOAP_INTERACTION_TEST_TARGET): tests/test_soap_interaction.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) tests/test_soap_interaction.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep -o $(SOAP_INTERACTION_TEST_TARGET)

$(REGISTER_TEST_TARGET): tests/test_register.c $(REGISTER_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-process.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) `pkg-config --cflags libzip` tests/test_register.c tests/vendor/munit/munit.c zapret-process.c util.c pfhash.c $(TEST_LDFLAGS) `pkg-config --libs libzip` -lidn2 -o $(REGISTER_TEST_TARGET)

test-sanitize: $(TEST_SANITIZER_TARGET) $(SOAP_TEST_SANITIZER_TARGET) $(SOAP_INTERACTION_TEST_SANITIZER_TARGET) $(REGISTER_TEST_SANITIZER_TARGET)
	./$(TEST_SANITIZER_TARGET)
	./$(SOAP_TEST_SANITIZER_TARGET)
	./$(SOAP_INTERACTION_TEST_SANITIZER_TARGET)
	./$(REGISTER_TEST_SANITIZER_TARGET)

$(TEST_SANITIZER_TARGET): tests/test_core.c tests/vendor/munit/munit.c tests/vendor/munit/munit.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_core.c tests/vendor/munit/munit.c util.c pfhash.c $(TEST_LDFLAGS) $(SANITIZER_FLAGS) -o $(TEST_SANITIZER_TARGET)

$(SOAP_TEST_SANITIZER_TARGET): tests/test_soap.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_soap.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl $(SANITIZER_FLAGS) -o $(SOAP_TEST_SANITIZER_TARGET)

$(SOAP_INTERACTION_TEST_SANITIZER_TARGET): tests/test_soap_interaction.c $(SOAP_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-soap.c zapret-checker.h zapret-structures.h util.c util.h sign.c sign.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) tests/test_soap_interaction.c tests/vendor/munit/munit.c zapret-soap.c util.c sign.c $(TEST_LDFLAGS) -ldl -Wl,--wrap=SendHTTPPost -Wl,--wrap=sleep $(SANITIZER_FLAGS) -o $(SOAP_INTERACTION_TEST_SANITIZER_TARGET)

$(REGISTER_TEST_SANITIZER_TARGET): tests/test_register.c $(REGISTER_TEST_FIXTURES) tests/vendor/munit/munit.c tests/vendor/munit/munit.h zapret-process.c zapret-checker.h zapret-structures.h util.c util.h pfhash.c pfhash.h allheaders.h dbg.h errorstrings.h
	$(CC) $(TEST_CFLAGS) $(SANITIZER_FLAGS) `pkg-config --cflags libzip` tests/test_register.c tests/vendor/munit/munit.c zapret-process.c util.c pfhash.c $(TEST_LDFLAGS) `pkg-config --libs libzip` -lidn2 $(SANITIZER_FLAGS) -o $(REGISTER_TEST_SANITIZER_TARGET)

clean:
	rm -rf $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET) $(TEST_TARGET) $(SOAP_TEST_TARGET) $(SOAP_INTERACTION_TEST_TARGET) $(REGISTER_TEST_TARGET) $(TEST_SANITIZER_TARGET) $(SOAP_TEST_SANITIZER_TARGET) $(SOAP_INTERACTION_TEST_SANITIZER_TARGET) $(REGISTER_TEST_SANITIZER_TARGET) $(OBJS) zapret-download.o zapret-configuration.h.include

install:
	install $(TARGET) $(DOWNLOAD_TARGET) $(SIGN_TARGET) $(PREFIX)/bin
#	mkdir -pv $(PREFIX)/bin/ $(PREFIX)/etc/$(TARGET)/
#	cp -vf $(CFG) $(PREFIX)/etc/$(TARGET)/
#	cp -vf ./$(TARGET).service /etc/systemd/system

uninstall:
	rm -rf $(PREFIX)/bin/$(TARGET)
	rm -rf $(PREFIX)/bin/$(DOWNLOAD_TARGET)
	rm -rf $(PREFIX)/bin/$(SIGN_TARGET)
	rm -rf /etc/systemd/system/$(TARGET).service
	rm -rf /etc/$(TARGET)/

$(SIGN_TARGET): rutoken-sign.c sign.c sign.h
	$(CC) rutoken-sign.c sign.c -ldl -o $(SIGN_TARGET)
