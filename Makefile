obj-m += mdev/
obj-m += cxgb4/
obj-m += e1000e/
obj-m += i40e/

UNAME_R := $(shell uname -r)

all:
	make -C /lib/modules/$(UNAME_R)/build M=$(PWD) V=1

clean:
	make -C /lib/modules/$(UNAME_R)/build M=~/odp-mdev-linux/ clean
	find -name *.mod | xargs rm > /dev/null 2>&1
