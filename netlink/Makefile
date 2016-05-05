
ifeq ($(KERNELDIR),)
KERNELDIR=	/lib/modules/$(shell uname -r)/source
endif


TARGET	:=	syskernelchk
PWD 	:= $(shell pwd)


ifneq ($(KERNELRELEASE),) 
	obj-m	:= LSP_netlink.o
#	obj-m	:= list_for_each.o
#	$(TARGET)-objs:= 
endif 

default: 
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=99 modules 
	@echo
	@echo build for $(ACCE_TARGET)
	@echo


clean: 
	@rm -rf *.ko *.mod.c *.mod.o *.o  .syskernel* .tmp* modules.* Module.* *.ko.unsigned .*.cmd
	
