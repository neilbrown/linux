#!/bin/sh

mkdir -p initramfs
cd initramfs || exit 1
rm -rf *

mkdir bin
ln -s bin sbin
# need busybox and findfs
p=`which busybox 2> /dev/null`
if [ -z "$p" ]; then
	echo "Please apt-get install busybox"
	exit 1
fi
echo "$p"
cp $p bin

p=`which findfs 2> /dev/null`
if [ -z "$p" ]; then
	echo "Please apt-get install util-linux"
	exit 1
fi
echo "$p"
cp $p bin

optional_bins="cryptsetup"
for i in $optional_bins; do
    p=`which $i 2> /dev/null`
    if [ -z "$p" ]; then
        echo "$i not found, not installing"
    else
        echo "$p"
        cp $p bin
    fi
done

for i in bin/*
do
  ldd $i | sed -n -e 's,^.*[ 	]\(/[^ ]*\) (.*$,\1,p'
done | while read lib
do
	if [ ! -f .$lib ]; then
		echo '## Adding' $lib
		mkdir -p `dirname .$lib`
		cp $lib .$lib
	fi
done

# now add all the names for busybox
busybox --list | while read a;
do ln -s busybox bin/$a
done

cat > init << "END"
#!/bin/busybox ash
# based on ALTERNATIVE PREINIT V1 - dgazineu gmail.com

gnubee_switch_root(){
  echo "Partition GNUBEE-ROOT found. Starting..." > /dev/kmsg
  r=`uname -r`
  if [ -d /mnt/root/lib/modules/$r ]
  then : skip
  else
     # ensure modules are available
     mount -t tmpfs tmpfs /mnt/root/lib/modules
     cp -a /lib/modules/. /mnt/root/lib/modules/
  fi
  umount /proc /sys /dev
  exec switch_root /mnt/root /sbin/init
}

gnubee_boot(){
   mount -t proc none /proc
   mount -t sysfs none /sys
   mount -t devtmpfs devtmpfs /dev

   modprobe ahci
   modprobe xhci_mtk
   modprobe usb_storage
   modprobe sd_mod
   modprobe ext4
   modprobe mtk_sd
   modprobe mmc_block

   echo "/sbin/mdev" > /proc/sys/kernel/hotplug
   mdev -s

   echo -n "Waiting disk spinup and searching for partition GNUBEE-ROOT..." > /dev/kmsg
   sleep 3
   echo "done." > /dev/kmsg

   echo "" > /proc/sys/kernel/hotplug

   sleep 1

   while true; do
       crypt_root=`findfs PARTLABEL=GNUBEE-CRYPT-ROOT`
       if test -n "$crypt_root"; then
           cryptsetup open "$crypt_root" rootdev
           root_dev="/dev/mapper/rootdev"
       else
           root_dev=`findfs LABEL=GNUBEE-ROOT`
       fi

       if test -n "$root_dev" &&
               mount -o ro $root_dev /mnt/root &&
               test -L /mnt/root/sbin/init -o -e /mnt/root/sbin/init &&
               gnubee_switch_root
       then break
       else /bin/ash # recovery shell
       fi
   done
}

gnubee_boot
END
chmod +x init
cd ..
cat > initramfs-files.txt << END
dir /dev 755 0 0
nod /dev/console 600 0 0 c 5 1
nod /dev/null 666 0 0 c 1 3
nod /dev/zero 666 0 0 c 1 5
nod /dev/tty 666 0 0 c 5 0
nod /dev/tty0 660 0 0 c 4 0
nod /dev/tty1 660 0 0 c 4 1
nod /dev/random 666 0 0 c 1 8
nod /dev/urandom 666 0 0 c 1 9
nod /dev/kmsg 666 0 0 c 1 11
dir /dev/pts 755 0 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /mnt 755 0 0
dir /mnt/root 755 0 0
END
tar czf gnubee-initramfs.tgz initramfs initramfs-files.txt
rm -rf initramfs initramfs-files.txt
ls -l gnubee-initramfs.tgz
cat << "END"
Please unpack this archive in the kernel source tree
After "make modules" run
  make INSTALL_MOD_PATH=initramfs modules_install
  make uImage
and arch/mips/boot/uImage.bin will be ready.
END
exit 0
