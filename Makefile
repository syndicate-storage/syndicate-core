include buildconf.mk

all: syndicate

syndicate: protobufs libsyndicate libsyndicate-ug ms syndicate-python

.PHONY: protobufs
protobufs:
	$(MAKE) -C protobufs

.PHONY: libsyndicate
libsyndicate: protobufs
	$(MAKE) -C libsyndicate

.PHONY: libsyndicate-ug
libsyndicate-ug: libsyndicate protobufs
	$(MAKE) -C libsyndicate-ug

.PHONY: ms
ms: protobufs 
	$(MAKE) -C ms

.PHONY: syndicate-python
syndicate-python: protobufs ms libsyndicate-ug libsyndicate
	$(MAKE) -C python

.PHONY: install
install:
	$(MAKE) -C protobufs install
	$(MAKE) -C libsyndicate install
	$(MAKE) -C libsyndicate-ug install
	$(MAKE) -C ms install
	$(MAKE) -C python install

.PHONY: clean
clean:
	$(MAKE) -C libsyndicate clean
	$(MAKE) -C protobufs clean
	$(MAKE) -C libsyndicate-ug clean
	$(MAKE) -C ms clean
	$(MAKE) -C python clean
	if [ -f docs/Makefile ]; then cd docs && make clean; fi

.PHONY: docs
docs:
	git submodule init
	git submodule update
	mkdir -p docs/sources/syndicate-core
	if [ ! -d docs/sources/syndicate-core/ms ]; then cp -r `find . -maxdepth 1 ! -name "docs" | grep /` docs/sources/syndicate-core; fi
	cd docs && make docs
