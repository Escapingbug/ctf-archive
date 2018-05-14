obj-m += exp.o
PWD = $(shell pwd)
source_dir = /lib/modules/`(uname -r)`/build/

all:
	make -C $(source_dir) M=$(PWD) modules

custom:
	make -C $(source_dir) M=$(PWD) modules

clean:
	make -C $(source_dir) M=$(PWD) clean
