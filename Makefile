obj-m += test_module.o

PWD  := $(shell pwd)
MOD_NAME := "test_module.ko"

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean