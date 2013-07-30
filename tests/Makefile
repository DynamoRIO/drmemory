obj-m := kernel_module.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) cleanDEPENDS/home/dtouch3d/dr/src/drmemory/build/tests/kernel_module