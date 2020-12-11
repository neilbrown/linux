ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"

ldlm_objs := l_lock.o ldlm_lock.o
ldlm_objs += ldlm_resource.o ldlm_lib.o
ldlm_objs += ldlm_plain.o ldlm_extent.o
ldlm_objs += ldlm_request.o ldlm_lockd.o
ldlm_objs += ldlm_flock.o ldlm_inodebits.o
ldlm_objs += ldlm_pool.o

ldlm_server_objs := ldlm_reclaim.o

ifneq "$(MODULES)" "ptlrpc"
endif
