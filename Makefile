CC       ?= clang
LDOPTS   += -Wl,-z,now -Wl,-z,relro -pie -pthread
COPTSWARN = -Wall -Wextra -Wno-unused-parameter -Wpointer-arith -Werror
COPTSSEC  = -D_FORTIFY_SOURCE=2

ifeq ($(CC), cc)
	CC = clang
endif

ifeq ($(CC), clang)
	COPTSSEC+=-fstack-protector-strong
else
	COPTSSEC+=-fstack-protector
endif

COPTSDEBUG=-g -ggdb -O0
ifeq ($(BUILD), debugaddress)
	COPTSDEBUG=-g -ggdb -O0 -fsanitize=address -fsanitize=undefined
endif
ifeq ($(BUILD), debugthread)
	COPTSDEBUG=-g -ggdb -O0 -fsanitize=thread -fsanitize=undefined
endif
ifeq ($(BUILD), release)
	MARCH=-march=corei7
	COPTSDEBUG=-g -ggdb -O3 $(MARCH)
endif

COPTS+=$(CFLAGS) $(COPTSDEBUG) $(COPTSWARN) $(COPTSSEC) -fPIE \
	-Ideps/libpcap

all: pmtud

pmtud: libpcap.a src/*.c src/*.h Makefile
	$(CC) $(COPTS) \
		src/main.c src/utils.c src/pcap.c src/uevent.c \
		libpcap.a \
		$(LDOPTS) \
		-o pmtud

libpcap.a: deps/libpcap
	(cd deps/libpcap && ./configure && make)
	cp deps/libpcap/libpcap.a .

clean:
	rm -rf pmtud

distclean: clean
	rm -f *.a *.o
	-(cd deps/libpcap && make clean && make distclean)
	-(cd deps/openonload && rm -rf build)

format:
	clang-format-3.5 -i src/*.c src/*.h
