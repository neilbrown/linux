# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(srctree)/$(src)/../include

obj-$(CONFIG_LUSTRE_FS) += obdclass.o

obdclass-y := llog.o llog_cat.o llog_obd.o llog_swab.o class_obd.o \
	      genops.o obd_sysfs.o lprocfs_status.o lprocfs_counters.o \
	      lustre_handles.o lustre_peer.o statfs_pack.o linkea.o \
	      obdo.o obd_config.o obd_mount.o lu_object.o lu_ref.o \
	      cl_object.o cl_page.o cl_lock.o cl_io.o kernelcomm.o \
	      jobid.o integrity.o obd_cksum.o lu_qos.o lu_tgt_descs.o
