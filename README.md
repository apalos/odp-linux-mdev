# compile #
* if /lib/modules/`uname -r`/build exists 
	* make all/clean
* if your kernel is on a custom path
	* make -C "kernel build dir" M=~/odp-mdev-linux/
	* make -C "kernel build dir" M=~/odp-mdev-linux/ clean
