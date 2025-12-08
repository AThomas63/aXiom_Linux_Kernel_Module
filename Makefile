USE_NEW ?= 0

KERNEL_LOC = /lib/modules/$(shell uname -r)/build/

ifeq ($(USE_NEW),1)
    # Only build new I2C module
    obj-m := axiom_i2c.o

    axiom_i2c-objs := axiom_core_new.o axiom_i2c_comms_new.o
else
    obj-m += axiom_usb.o
    obj-m += axiom_spi.o
    obj-m += axiom_i2c.o

    CORE_SRC := axiom_core.o
    axiom_usb-objs := $(CORE_SRC) axiom_usb_comms.o
    axiom_spi-objs := $(CORE_SRC) axiom_spi_comms.o
    axiom_i2c-objs := $(CORE_SRC) axiom_i2c_comms.o
endif

all:
	$(MAKE) -C $(KERNEL_LOC) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNEL_LOC) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_LOC) M=$(PWD) clean