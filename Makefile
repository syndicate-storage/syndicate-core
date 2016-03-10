include buildconf.mk

all: syndicate

syndicate: protobufs libsyndicate

.PHONY: protobufs
protobufs:
	$(MAKE) -C protobufs

.PHONY: libsyndicate
libsyndicate: protobufs
	$(MAKE) -C libsyndicate

.PHONY: clean
clean:
	$(MAKE) -C libsyndicate clean
	$(MAKE) -C protobufs clean

