ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
fld-objs := fld_request.o fld_cache.o lproc_fld.o

fld-y = $(fld-objs)
obj-$(CONFIG_LUSTRE_FS) += fld.o
