
libcfs-linux-objs := linux-prim.o
libcfs-linux-objs += linux-curproc.o
libcfs-linux-objs += linux-hash.o
libcfs-linux-objs += linux-wait.o
libcfs-linux-objs += xarray.o

libcfs-linux-objs := $(addprefix linux/,)

libcfs-all-objs := debug.o fail.o module.o tracefile.o \
		   libcfs_string.o hash.o \
		   linux-crypto.o linux-crypto-adler.o

libcfs-objs :=  $(libcfs-all-objs)

libcfs-y = $(libcfs-objs)
obj-$(CONFIG_LNET) += libcfs.o
