CPPFLAGS = -Wall -Wextra

all: hydrogen.so

libhydrogen/libhydrogen.a: libhydrogen/
	$(MAKE) -C libhydrogen CFLAGS=-fPIC

hydrogen.so: src/lh.c libhydrogen/hydrogen.h libhydrogen/libhydrogen.a
	gcc -shared -fPIC $(CPPFLAGS) $(CFLAGS) -I libhydrogen/ $< libhydrogen/libhydrogen.a -o "$@"

check: hydrogen.so
	lua test.lua

clean:
	rm -f hydrogen.so
	$(MAKE) -C libhydrogen clean
