
ifeq ($(KERNELDIR),)
KERNELDIR=	/lib/modules/$(shell uname -r)/source
endif


TARGET	:=	firewall
PWD 	:= $(shell pwd)


ifneq ($(KERNELRELEASE),) 
	obj-m	:= $(TARGET).o
	$(TARGET)-objs:= netfilter/filter.o netlink/LSP_netlink.o
endif 

default: 
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=0 modules 
	@echo
	@echo build for $(ACCE_TARGET)
	@echo


clean: 
	@rm -rf  *.ko *.mod.c *.mod.o *.o  .syskernel* .tmp* modules.* Module.* *.ko.unsigned .*.cmd ./*/.*.cmd ./*/*.o
	