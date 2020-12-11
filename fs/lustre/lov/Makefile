ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
lov-objs := lov_dev.o \
	lov_ea.o \
	lov_io.o \
	lov_lock.o \
	lov_merge.o \
	lov_obd.o \
	lov_object.o \
	lov_offset.o \
	lov_pack.o \
	lov_page.o \
	lov_pool.o \
	lov_request.o \
	lovsub_dev.o \
	lovsub_object.o \
	lproc_lov.o

lov-y = $(lov-objs)
obj-$(CONFIG_LUSTRE_FS) += lov.o
