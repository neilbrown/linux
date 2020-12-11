ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
lmv-objs := lmv_obd.o lmv_intent.o lmv_fld.o lproc_lmv.o

lmv-y = $(lmv-objs)
obj-$(CONFIG_LUSTRE_FS) += lmv.o
