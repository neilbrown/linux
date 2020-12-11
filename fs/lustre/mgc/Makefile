ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
mgc-objs := mgc_request.o lproc_mgc.o

mgc-y = $(mgc-objs)
obj-$(CONFIG_LUSTRE_FS) += mgc.o
