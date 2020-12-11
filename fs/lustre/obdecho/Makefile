ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"
obdecho-objs := echo_client.o debug.o

obdecho-y = $(obdecho-objs)
obj-$(CONFIG_LUSTRE_FS) += obdecho.o
