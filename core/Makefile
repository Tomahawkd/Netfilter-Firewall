ifndef MAKEFILE_CORE
define MAKEFILE_CORE
yes
endef

PWD  := $(shell pwd)
NAME = firewallmodule

obj-m += $(NAME).o
$(NAME)-objs := module.o

MOD_NAME := $(NAME).ko

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif