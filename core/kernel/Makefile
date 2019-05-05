ifndef MAKEFILE_CORE
define MAKEFILE_CORE
yes
endef

obj-m += test_module.o

PWD  := $(shell pwd)
MOD_NAME := "test_module.ko"

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir ../bin
	cp $(MOD_NAME) ../bin

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif