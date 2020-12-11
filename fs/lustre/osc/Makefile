ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
osc-objs := osc_request.o lproc_osc.o osc_dev.o osc_object.o osc_page.o osc_lock.o osc_io.o osc_quota.o osc_cache.o

osc-y = $(osc-objs)
obj-$(CONFIG_LUSTRE_FS) += osc.o
