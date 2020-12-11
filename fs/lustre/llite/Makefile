ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
lustre-objs := dcache.o dir.o file.o llite_lib.o llite_nfs.o
lustre-objs += rw.o lproc_llite.o namei.o symlink.o llite_mmap.o
lustre-objs += xattr.o xattr_cache.o
lustre-objs += rw26.o super25.o statahead.o xattr_security.o
lustre-objs += glimpse.o
lustre-objs += lcommon_cl.o
lustre-objs += lcommon_misc.o
lustre-objs += vvp_dev.o vvp_page.o vvp_io.o vvp_object.o
lustre-objs += range_lock.o pcc.o crypto.o

lustre-$(CONFIG_FS_POSIX_ACL) += acl.o
lustre-objs += $(lustre-y)

lustre-y = $(lustre-objs)
obj-$(CONFIG_LUSTRE_FS) += lustre.o
