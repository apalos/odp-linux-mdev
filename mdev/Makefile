# linaro add our includes
ccflags-y += -I$(PWD)/include -DCONFIG_VFIO_MDEV_NET_DEVICE_MODULE
mdev-y := mdev_core.o mdev_sysfs.o mdev_driver.o

obj-$(CONFIG_VFIO_MDEV) += mdev.o
obj-$(CONFIG_VFIO_MDEV_DEVICE) += vfio_mdev.o
obj-m += vfio_net_mdev.o
