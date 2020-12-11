ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"

obdclass-all-objs := llog.o llog_cat.o llog_obd.o llog_swab.o
obdclass-all-objs += class_obd.o genops.o
obdclass-all-objs += lprocfs_status.o lprocfs_counters.o
obdclass-all-objs += lustre_handles.o lustre_peer.o
obdclass-all-objs += statfs_pack.o obdo.o obd_config.o obd_mount.o obd_sysfs.o
obdclass-all-objs += lu_object.o
obdclass-all-objs += cl_object.o cl_page.o cl_lock.o cl_io.o lu_ref.o
obdclass-all-objs += linkea.o
obdclass-all-objs += kernelcomm.o jobid.o
obdclass-all-objs += integrity.o obd_cksum.o
obdclass-all-objs += lu_tgt_descs.o

obdclass-objs := $(obdclass-all-objs)

obdclass-y = $(obdclass-objs)
obj-$(CONFIG_LUSTRE_FS) += obdclass.o
