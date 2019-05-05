ifndef MAKEFILE_CORE
define MAKEFILE_CORE
yes
endef

NAME = module

obj-m += $(NAME).o
$(NAME)-objs := test_module.o

PWD  := $(shell pwd)
MOD_NAME := $(NAME).ko

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif