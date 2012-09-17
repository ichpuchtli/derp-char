INDENT = -kr -i8 -l79 -lc79

obj-m += crypto.o
crypto-objs := crypto-ops.o crypto-mod.o

MOD_DIR=/lib/modules/$(shell uname -r)/build

.PHONY: all
all: 
	cp cryptodev-1.0/Module.symvers .
	@make -C $(MOD_DIR) M=$(PWD) modules

.PHONY: clean
clean: 
	@make -C $(MOD_DIR) M=$(PWD) clean
	rm -f _*

indent:
	dos2unix crypto-*
	indent $(INDENT) crypto-mod.c -o _crypto-mod.c
	indent $(INDENT) crypto-ops.c -o _crypto-ops.c
	indent $(INDENT) crypto-ops.h -o _crypto-ops.h

merge: indent
	rename -f 's/^_//' _crypto-*	

check: merge
	perl checkpatch-0.32.pl --no-tree --no-signoff -f --no-summary crypto-*
