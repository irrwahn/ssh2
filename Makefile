LDFLAGS=libssh2/lib/libssh2.a -lssl -lcrypto -lz
#LDFLAGS=-lssh2 -lssl -lcrypto -lz
LDFLAGS_ARM=libssh2/lib.arm/libssh2.a -Llibssh2/lib.arm -lssl -lcrypto -lz
CFLAGS=-I libssh2/include -W -Wall -Wextra -DWITH_TUNNEL -DDEBUG
CFLAGS_ARM=$(CFLAGS)
ARM_BIN=/opt/arm-2012.09/bin/
CC_ARM=$(ARM_BIN)arm-none-linux-gnueabi-gcc
STRIP=strip
STRIP_ARM=$(ARM_BIN)arm-none-linux-gnueabi-strip

TARGETS=ssh2 ssh2.arm

.PHONY: all clean strip install.arm

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

ssh2: ssh2.c net.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

ssh2.arm: ssh2.c net.c
	$(CC_ARM) $(CFLAGS_ARM) $^ $(LDFLAGS_ARM) -o $@

strip: all
	$(STRIP_ARM) ssh2.arm
	$(STRIP) ssh2

install.arm: ssh2.arm
	scp -P4672 ssh2.arm cradle2:/tmp/ssh2
