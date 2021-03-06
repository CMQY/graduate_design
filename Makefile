
ifeq ($(KERNELDIR),)
KERNELDIR=	/lib/modules/$(shell uname -r)/source
endif


TARGET	:=	firewall
PWD 	:= $(shell pwd)


ifneq ($(KERNELRELEASE),) 
	obj-m	:= $(TARGET).o
	$(TARGET)-objs:= netfilter/filter.o netlink/LSP_netlink.o proc/LSP_proc.o
endif 

default: 
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=0 modules 
	gcc ./userspace/LSP_controller.c -o ./userspace/lsp_controller
	@rm -rf  *.mod.c *.mod.o *.o  .syskernel* .tmp* modules.* Module.* *.ko.unsigned .*.cmd ./*/.*.cmd ./*/*.o 


clean: 
	@rm -rf  *.ko *.mod.c *.mod.o *.o  .syskernel* .tmp* modules.* Module.* *.ko.unsigned .*.cmd ./*/.*.cmd ./*/*.o ./userspace/lsp_controller
	
