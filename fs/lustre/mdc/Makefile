ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"

mdc-objs-y :=	mdc_request.o \
		mdc_reint.o \
		lproc_mdc.o \
		mdc_lib.o \
		mdc_locks.o \
		mdc_changelog.o \
		mdc_dev.o

mdc-objs-$(CONFIG_FS_POSIX_ACL) += mdc_acl.o

mdc-objs := $(mdc-objs-y)

mdc-y = $(mdc-objs)
obj-$(CONFIG_LUSTRE_FS) += mdc.o
