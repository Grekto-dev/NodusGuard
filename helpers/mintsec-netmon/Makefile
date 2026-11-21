CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

all: mintsec-netmon

mintsec-netmon: mintsec_netmon.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f mintsec-netmon
