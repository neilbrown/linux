ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
fid-objs := fid_request.o lproc_fid.o

fid-y = $(fid-objs)
obj-$(CONFIG_LUSTRE_FS) += fid.o
