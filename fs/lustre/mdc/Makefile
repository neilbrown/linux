ccflags-y += -I$(srctree)/$(src)/../include

obj-$(CONFIG_LUSTRE_FS) += mdc.o
mdc-y := mdc_changelog.o mdc_request.o mdc_reint.o mdc_lib.o mdc_locks.o lproc_mdc.o
mdc-y += mdc_dev.o
mdc-$(CONFIG_LUSTRE_FS_POSIX_ACL) += mdc_acl.o
