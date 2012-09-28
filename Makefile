INDENT = -kr -i8 -l79 -lc79

obj-m += crypto.o
crypto-objs := crypto-ops.o crypto-mod.o

MOD_DIR=/lib/modules/$(shell uname -r)/build
KBUILD_EXTMOD=$(PWD)/cryptodev-1.0

.PHONY: all
all: 
	@make -C $(MOD_DIR) M=$(PWD) modules

.PHONY: clean
clean: 
	@make -C $(MOD_DIR) M=$(PWD) clean
