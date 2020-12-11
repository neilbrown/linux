
lnet-objs-$(CONFIG_SMP) = lib-cpu.o

lnet-objs := api-ni.o config.o nidstrings.o lock.o
lnet-objs += lib-me.o lib-msg.o lib-md.o lib-ptl.o
lnet-objs += lib-socket.o lib-move.o module.o lo.o
lnet-objs += router.o router_proc.o acceptor.o peer.o net_fault.o
lnet-objs += lib-mem.o $(lnet-objs-y)

lnet-y = $(lnet-objs)
obj-$(CONFIG_LNET) += lnet.o
