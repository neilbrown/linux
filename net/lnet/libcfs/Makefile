# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_LNET) += libcfs.o

libcfs-obj-y += linux-crypto.o
libcfs-obj-y += linux-crypto-adler.o

libcfs-obj-y += debug.o fail.o module.o tracefile.o
libcfs-obj-y += libcfs_string.o
libcfs-obj-$(CONFIG_SMP) += libcfs_cpu.o
libcfs-obj-y += libcfs_mem.o libcfs_lock.o

libcfs-objs := $(libcfs-obj-y)
