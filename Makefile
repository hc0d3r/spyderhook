CFLAGS+=-Wall -Wextra -O2
VERSION = 0.1.0
OBJ = spyderhook.o
SHARED_OBJ = libspyderhook.so
STATIC_OBJ = libspyderhook.a
SHARED_OBJV = $(SHARED_OBJ).$(VERSION)

ifeq ($(PREFIX),)
    PREFIX := /usr
endif

.PHONY: all
all: lib/$(STATIC_OBJ) lib/$(SHARED_OBJ)

lib/$(STATIC_OBJ): lib/$(OBJ)
	ar rcs $@ $<

lib/$(SHARED_OBJ): lib/$(SHARED_OBJV)
	cd lib; ln -sf $(SHARED_OBJV) $(SHARED_OBJ)

lib/$(SHARED_OBJV): lib/$(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(SHARED_OBJV) -o $@ $^

lib/%.o: src/%.c src/%.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -c -o $@ $<

.PHONY: install
install: all
	install -d $(PREFIX)/lib
	install lib/$(STATIC_OBJ) $(PREFIX)/lib
	install lib/$(SHARED_OBJV) $(PREFIX)/lib
	install lib/$(SHARED_OBJ) $(PREFIX)/lib

	install -d $(PREFIX)/include
	install -m 644 src/spyderhook.h $(PREFIX)/include

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/lib/$(STATIC_OBJ) \
		$(PREFIX)/lib/$(SHARED_OBJV) \
		$(PREFIX)/lib/$(SHARED_OBJ) \
		$(PREFIX)/include/spyderhook.h

.PHONY: clean
clean:
	cd lib && rm -f $(OBJ) $(SHARED_OBJV) $(SHARED_OBJ) $(STATIC_OBJ)
