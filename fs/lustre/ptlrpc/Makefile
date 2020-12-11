ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
ptlrpc_dir := $(dir $(lastword $(MAKEFILE_LIST)))
LDLM := ../../lustre/ldlm/
TARGET := ../../lustre/target/

ptlrpc_objs := client.o recover.o connection.o niobuf.o pack_generic.o
ptlrpc_objs += events.o ptlrpc_module.o service.o pinger.o
ptlrpc_objs += llog_net.o llog_client.o import.o ptlrpcd.o
ptlrpc_objs += pers.o lproc_ptlrpc.o wiretest.o layout.o
ptlrpc_objs += sec.o sec_bulk.o sec_gc.o sec_config.o sec_lproc.o
ptlrpc_objs += sec_null.o sec_plain.o nrs.o nrs_fifo.o
ptlrpc_objs += errno.o

nrs_objs := nrs_crr.o nrs_orr.o nrs_tbf.o nrs_delay.o heap.o

nodemap_objs := nodemap_handler.o nodemap_lproc.o nodemap_range.o
nodemap_objs += nodemap_idmap.o nodemap_rbtree.o nodemap_member.o
nodemap_objs += nodemap_storage.o

include $(ptlrpc_dir)/../ldlm/Makefile

ptlrpc_server-objs := llog_server.o sec_ctx.o

ptlrpc-objs := $(ptlrpc_objs)
ptlrpc-objs += $(patsubst %,$(LDLM)%,$(ldlm_objs))

ptlrpc-y = $(ptlrpc-objs)
obj-$(CONFIG_LUSTRE_FS) += ptlrpc.o
