ccflags-y += -I$(srctree)/$(src)/../include -DLUSTRE_MAJOR=2 -DLUSTRE_MINOR=13 -DLUSTRE_PATCH=53 -DLUSTRE_FIX=0 -DLUSTRE_VERSION_STRING=\"2.13.53\"

am__is_gnu_make = { \
  if test -z '$(MAKELEVEL)'; then \
    false; \
  elif test -n '$(MAKE_HOST)'; then \
    true; \
  elif test -n '$(MAKE_VERSION)' && test -n '$(CURDIR)'; then \
    true; \
  else \
    false; \
  fi; \
}
am__make_running_with_option = \
  case $${target_option-} in \
      ?) ;; \
      *) echo "am__make_running_with_option: internal error: invalid" \
              "target option '$${target_option-}' specified" >&2; \
         exit 1;; \
  esac; \
  has_opt=no; \
  sane_makeflags=$$MAKEFLAGS; \
  if $(am__is_gnu_make); then \
    sane_makeflags=$$MFLAGS; \
  else \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        bs=\\; \
        sane_makeflags=`printf '%s\n' "$$MAKEFLAGS" \
          | sed "s/$$bs$$bs[$$bs $$bs	]*//g"`;; \
    esac; \
  fi; \
  skip_next=no; \
  strip_trailopt () \
  { \
    flg=`printf '%s\n' "$$flg" | sed "s/$$1.*$$//"`; \
  }; \
  for flg in $$sane_makeflags; do \
    test $$skip_next = yes && { skip_next=no; continue; }; \
    case $$flg in \
      *=*|--*) continue;; \
        -*I) strip_trailopt 'I'; skip_next=yes;; \
      -*I?*) strip_trailopt 'I';; \
        -*O) strip_trailopt 'O'; skip_next=yes;; \
      -*O?*) strip_trailopt 'O';; \
        -*l) strip_trailopt 'l'; skip_next=yes;; \
      -*l?*) strip_trailopt 'l';; \
      -[dEDm]) skip_next=yes;; \
      -[JT]) skip_next=yes;; \
    esac; \
    case $$flg in \
      *$$target_option*) has_opt=yes; break;; \
    esac; \
  done; \
  test $$has_opt = yes
am__make_dryrun = (target_option=n; $(am__make_running_with_option))
am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
pkgdatadir = $(datadir)/lustre
pkgincludedir = $(includedir)/lustre
pkglibdir = $(libdir)/lustre
pkglibexecdir = $(libexecdir)/lustre
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-pc-linux-gnu
host_triplet = x86_64-pc-linux-gnu
target_triplet = x86_64-pc-linux-gnu
subdir = lustre/include
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
DIST_COMMON = $(srcdir)/Makefile.am $(am__DIST_COMMON)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
AM_V_P = $(am__v_P_$(V))
am__v_P_ = $(am__v_P_$(AM_DEFAULT_VERBOSITY))
am__v_P_0 = false
am__v_P_1 = :
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN     " $@;
am__v_GEN_1 = 
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
am__v_at_1 = 
SOURCES =
DIST_SOURCES =
RECURSIVE_TARGETS = all-recursive check-recursive cscopelist-recursive \
	ctags-recursive dvi-recursive html-recursive info-recursive \
	install-data-recursive install-dvi-recursive \
	install-exec-recursive install-html-recursive \
	install-info-recursive install-pdf-recursive \
	install-ps-recursive install-recursive installcheck-recursive \
	installdirs-recursive pdf-recursive ps-recursive \
	tags-recursive uninstall-recursive
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
RECURSIVE_CLEAN_TARGETS = mostlyclean-recursive clean-recursive	\
  distclean-recursive maintainer-clean-recursive
am__recursive_targets = \
  $(RECURSIVE_TARGETS) \
  $(RECURSIVE_CLEAN_TARGETS) \
  $(am__extra_recursive_targets)
AM_RECURSIVE_TARGETS = $(am__recursive_targets:-recursive=) TAGS CTAGS \
	distdir distdir-am
am__tagged_files = $(HEADERS) $(SOURCES) $(TAGS_FILES) $(LISP)
am__uniquify_input = $(AWK) '\
  BEGIN { nonempty = 0; } \
  { items[$$0] = 1; nonempty = 1; } \
  END { if (nonempty) { for (i in items) print i; }; } \
'
am__define_uniq_tagged_files = \
  list='$(am__tagged_files)'; \
  unique=`for i in $$list; do \
    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
  done | $(am__uniquify_input)`
ETAGS = etags
CTAGS = ctags
am__DIST_COMMON = $(srcdir)/Makefile.in
am__relativize = \
  dir0=`pwd`; \
  sed_first='s,^\([^/]*\)/.*$$,\1,'; \
  sed_rest='s,^[^/]*/*,,'; \
  sed_last='s,^.*/\([^/]*\)$$,\1,'; \
  sed_butlast='s,/*[^/]*$$,,'; \
  while test -n "$$dir1"; do \
    first=`echo "$$dir1" | sed -e "$$sed_first"`; \
    if test "$$first" != "."; then \
      if test "$$first" = ".."; then \
        dir2=`echo "$$dir0" | sed -e "$$sed_last"`/"$$dir2"; \
        dir0=`echo "$$dir0" | sed -e "$$sed_butlast"`; \
      else \
        first2=`echo "$$dir2" | sed -e "$$sed_first"`; \
        if test "$$first2" = "$$first"; then \
          dir2=`echo "$$dir2" | sed -e "$$sed_rest"`; \
        else \
          dir2="../$$dir2"; \
        fi; \
        dir0="$$dir0"/"$$first"; \
      fi; \
    fi; \
    dir1=`echo "$$dir1" | sed -e "$$sed_rest"`; \
  done; \
  reldir="$$dir2"
ACLOCAL = ${SHELL} /home/git/lustre-release/config/missing aclocal-1.16
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 1
AR = ar
AUTOCONF = ${SHELL} /home/git/lustre-release/config/missing autoconf
AUTOCONF_HDIR = generated
AUTOHEADER = ${SHELL} /home/git/lustre-release/config/missing autoheader
AUTOMAKE = ${SHELL} /home/git/lustre-release/config/missing automake-1.16
AWK = gawk
BASH_COMPLETION_DIR = /usr/share/bash-completion/completions
CC = gcc
CCAS = gcc
CCASDEPMODE = depmode=gcc3
CCASFLAGS = -Wall -fPIC -D_GNU_SOURCE
CCDEPMODE = depmode=gcc3
CFLAGS = -g -O2 -Wall -Werror
CONFIG_INCLUDE = /home2/git/lustre-build/include/linux/kconfig.h
CPP = gcc -E
CPPFLAGS = -include /home/git/lustre-release/undef.h -include /home/git/lustre-release/config.h -I/home/git/lustre-release/lnet/include/uapi -I/home/git/lustre-release/lustre/include/uapi -I/home/git/lustre-release/libcfs/include -I/home/git/lustre-release/lnet/utils -I/home/git/lustre-release/lustre/include 
CYGPATH_W = echo
DEBUGFS = debugfs
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = false
DSYMUTIL = 
DUMPBIN = 
DUMPE2FS = dumpe2fs
E2FSCK = e2fsck
E2FSPROGS = e2fsprogs
E2LABEL = e2label
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /usr/bin/grep -E
ENABLEO2IB = no
ENABLE_CRYPTO = yes
ENABLE_DOC = 0
ENABLE_GSS = yes
ENABLE_LDISKFS = no
ENABLE_SERVER = no
ENABLE_ZFS = no
EXEEXT = 
EXT4_SRC_DIR = 
EXTRA_KCFLAGS = -include /home/git/lustre-release/undef.h -include /home/git/lustre-release/config.h  -g -I/home/git/lustre-release/libcfs/include -I/home/git/lustre-release/libcfs/include/libcfs -I/home/git/lustre-release/lnet/include/uapi -I/home/git/lustre-release/lnet/include -I/home/git/lustre-release/lustre/include/uapi -I/home/git/lustre-release/lustre/include -Wno-format-truncation -Wno-stringop-truncation -Wno-stringop-overflow
EXTRA_OFED_CONFIG = 
EXTRA_OFED_INCLUDE = 
EXTRA_SYMBOLS = 
FGREP = /usr/bin/grep -F
GNICPPFLAGS = 
GNILND = 
GREP = /usr/bin/grep
INCLUDE_RULES = include /home/git/lustre-release/Rules
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
K5VERS = 1182
KMODEXT = .ko
KMP_MODDIR = 
KRBCFLAGS = 
KRBDIR = /usr
KRBLDFLAGS = 
KRBLIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
LD = /usr/x86_64-suse-linux/bin/ld -m elf_x86_64
LDFLAGS = 
LDISKFS_SERIES = 
LDISKFS_SUBDIR = 
LDLIBMOUNT = -lmount
LIBEFENCE = 
LIBOBJS = 
LIBREADLINE = -lreadline
LIBS = -lkeyutils -lkeyutils 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LINUX = /home2/git/lustre-build
LINUXRELEASE = 5.10.0-rc7-00002-gcd796ed33450
LINUX_CONFIG = /home2/git/lustre-build/O/.config
LINUX_OBJ = /home2/git/lustre-build/O
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
LT_SYS_LIBRARY_PATH = 
LUSTRE = /home/git/lustre-release/lustre
LUSTREIOKIT_SUBDIR = lustre-iokit
MAINT = 
MAKEINFO = ${SHELL} /home/git/lustre-release/config/missing makeinfo
MANIFEST_TOOL = :
MKDIR_P = /usr/bin/mkdir -p
MKE2FS = mke2fs
MODULE_TARGET = M
MOSTLYCLEANFILES = .*.cmd .*.flags *.o *.ko *.mod.c .depend .*.1.* Modules.symvers Module.symvers
MPICC_WRAPPER = mpicc
MPI_BIN = .
NET_SNMP_CFLAGS = -O2 -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -funwind-tables -fasynchronous-unwind-tables -fstack-clash-protection -Werror=return-type -flto=auto -g -fcommon -DNETSNMP_ENABLE_IPV6 -fno-strict-aliasing -DNETSNMP_REMOVE_U64 -O2 -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -funwind-tables -fasynchronous-unwind-tables -fstack-clash-protection -flto=auto -g -fcommon -Ulinux -Dlinux=linux -D_REENTRANT -D_GNU_SOURCE -DPERL_USE_SAFE_PUTENV -fwrapv -fno-strict-aliasing -pipe -fstack-protector-strong -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I/usr/lib/perl5/5.32.0/x86_64-linux-thread-multi/CORE -I/usr/include
NET_SNMP_CONFIG = net-snmp-config
NET_SNMP_LIBS = -Wl,-z,relro -Wl,-z,now -L/usr/lib64 -lnetsnmpmibs -lsensors -ldl -lrpm -lrpmio -lnetsnmpagent -L/usr/lib -lwrap -Wl,-E -Wl,-rpath,/usr/lib/perl5/5.32.0/x86_64-linux-thread-multi/CORE -lnetsnmp -lssl -lssl -lcrypto -lm
NM = /usr/bin/nm -B
NMEDIT = 
O2IBLND = 
O2IBPATH = 
OBJDUMP = objdump
OBJEXT = o
OSDADDON = 
OTOOL = 
OTOOL64 = 
PACKAGE = lustre
PACKAGE_BUGREPORT = https://jira.whamcloud.com/
PACKAGE_NAME = Lustre
PACKAGE_STRING = Lustre 2.13.57_118_gffbaa89
PACKAGE_TARNAME = lustre
PACKAGE_URL = 
PACKAGE_VERSION = 2.13.57_118_gffbaa89
PATCHED_INTEGRITY_INTF = #
PATH_SEPARATOR = :
PFSCK = fsck
PKG_CONFIG = /usr/bin/pkg-config
PKG_CONFIG_LIBDIR = 
PKG_CONFIG_PATH = 
PTHREAD_LIBS = -lpthread
PYTHON = /usr/bin/python3
PYTHON_CPPFLAGS = -I/usr/include/python3.8
PYTHON_EXTRA_LDFLAGS = -Xlinker -export-dynamic
PYTHON_EXTRA_LIBS = -lcrypt -lpthread -ldl  -lutil -lm -lm
PYTHON_LIBS = -L/usr/lib64 -lpython3.8
PYTHON_SITE_PKG = /usr/lib/python3.8/site-packages
PYTHON_VERSION_CHECK = yes
RANLIB = ranlib
RPMBUILD = /usr/bin/rpmbuild
RPMBUILD_BINARY_ARGS =  --define "configure_args  '-with-o2ib=no'" --define "kdir /home2/git/lustre-build" --define "kobjdir /home2/git/lustre-build/O" --without servers --without ldiskfs --with gss_keyring --with gss --with gss --with crypto --without snmp --without mpi
SED = /usr/bin/sed
SELINUX = -lselinux
SET_MAKE = 
SHELL = /bin/sh
SNMP_DIST_SUBDIR = snmp
SNMP_SUBDIR = 
SPL = 
SPL_OBJ = 
SPL_VERSION = 
STRIP = strip
SWIG = /usr/bin/swig
SWIG_LIB = /usr/share/swig/4.0.2
SYMVERFILE = Module.symvers
TEST_DIR = /home/git/lustre-release/_lpb
TEST_JOBS = 16
TUNE2FS = tune2fs
VERSION = 2.13.57_118_gffbaa89
VERSION_HDIR = generated/uapi/linux
ZFS = 
ZFS_LIBZFS_INCLUDE = 
ZFS_LIBZFS_LDFLAGS = 
ZFS_LIBZFS_LIBS = 
ZFS_OBJ = 
ZFS_VERSION = 
abs_builddir = /home/git/lustre-release/lustre/include
abs_srcdir = /home/git/lustre-release/lustre/include
abs_top_builddir = /home/git/lustre-release
abs_top_srcdir = /home/git/lustre-release
ac_configure_args =  '--with-linux=/home2/git/lustre-build' '--with-linux-obj=/home2/git/lustre-build/O' '--disable-server' '-with-o2ib=no'
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_DUMPBIN = 
agentdir = ${pkglibdir}/snmp
am__include = include
am__leading_dot = .
am__quote = 
am__tar = tar --format=ustar -chf - "$$tardir"
am__untar = tar -xf -
bindir = ${exec_prefix}/bin
build = x86_64-pc-linux-gnu
build_alias = 
build_cpu = x86_64
build_os = linux-gnu
build_vendor = pc
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
demodir = $(docdir)/demo
docdir = ${datadir}/doc/$(PACKAGE)
dvidir = ${docdir}
exec_prefix = ${prefix}
host = x86_64-pc-linux-gnu
host_alias = 
host_cpu = x86_64
host_os = linux-gnu
host_vendor = pc
htmldir = ${docdir}
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/git/lustre-release/config/install-sh
lb_target_os = linux
libdir = ${exec_prefix}/lib64
libexecdir = ${exec_prefix}/lib
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mibdir = ${pkgdatadir}/snmp/mibs
mkdir_p = $(MKDIR_P)
modulefsdir = /lib/modules/5.10.0-rc7-00002-gcd796ed33450//fs/lustre
modulenetdir = /lib/modules/5.10.0-rc7-00002-gcd796ed33450//net/lustre
oldincludedir = /usr/include
patch_avail = 
pdfdir = ${docdir}
pkgexampledir = ${pkgdatadir}/examples
prefix = /usr
program_transform_name = s,x,x,
psdir = ${docdir}
quilt_avail = 
rootsbindir = /sbin
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = /etc
systemdsystemunitdir = /usr/lib/systemd/system
target = x86_64-pc-linux-gnu
target_alias = 
target_cpu = x86_64
target_os = linux-gnu
target_vendor = pc
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
SUBDIRS = lustre uapi/linux/lustre
DIST_SUBDIRS = lustre uapi/linux/lustre
	cl_object.h \
	dt_object.h \
	llog_swab.h \
	lprocfs_status.h \
	lu_object.h \
	lu_ref.h \
	lustre_acl.h \
	lustre_barrier.h \
	lustre_compat.h \
	lustre_crypto.h \
	lustre_disk.h \
	lustre_dlm_flags.h \
	lustre_dlm.h \
	lustre_eacl.h \
	lustre_errno.h \
	lustre_export.h \
	lustre_fid.h \
	lustre_fld.h \
	lustre_ha.h \
	lustre_handles.h \
	lustre_idmap.h \
	lustre_import.h \
	lustre_intent.h \
	lustre_lfsck.h \
	lustre_lib.h \
	lustre_linkea.h \
	lustre_lmv.h \
	lustre_log.h \
	lustre_mdc.h \
	lustre_mds.h \
	lustre_net.h \
	lustre_osc.h \
	lustre_nodemap.h \
	lustre_nrs.h \
	lustre_nrs_crr.h \
	lustre_nrs_delay.h \
	lustre_nrs_fifo.h \
	lustre_nrs_orr.h \
	lustre_nrs_tbf.h \
	lustre_obdo.h \
	lustre_quota.h \
	lustre_req_layout.h \
	lustre_scrub.h \
	lustre_sec.h \
	lustre_swab.h \
	lustre_update.h \
	lustre_wait.h \
	lu_target.h \
	lvfs.h \
	md_object.h \
	obd_cache.h \
	obd_cksum.h \
	obd_class.h \
	obd.h \
	obd_support.h \
	obd_target.h \
	obj_update.h \
	upcall_cache.h \
	lustre_kernelcomm.h \
	seq_range.h

all: all-recursive

.SUFFIXES:
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --gnu lustre/include/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --gnu lustre/include/Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__maybe_remake_depfiles)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__maybe_remake_depfiles);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

$(am__recursive_targets):
	@fail=; \
	if $(am__make_keepgoing); then \
	  failcom='fail=yes'; \
	else \
	  failcom='exit 1'; \
	fi; \
	dot_seen=no; \
	target=`echo $@ | sed s/-recursive//`; \
	case "$@" in \
	  distclean-* | maintainer-clean-*) list='$(DIST_SUBDIRS)' ;; \
	  *) list='$(SUBDIRS)' ;; \
	esac; \
	for subdir in $$list; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    dot_seen=yes; \
	    local_target="$$target-am"; \
	  else \
	    local_target="$$target"; \
	  fi; \
	  ($(am__cd) $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target) \
	  || eval $$failcom; \
	done; \
	if test "$$dot_seen" = "no"; then \
	  $(MAKE) $(AM_MAKEFLAGS) "$$target-am" || exit 1; \
	fi; test -z "$$fail"

ID: $(am__tagged_files)
	$(am__define_uniq_tagged_files); mkid -fID $$unique
tags: tags-recursive
TAGS: tags

tags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	set x; \
	here=`pwd`; \
	if ($(ETAGS) --etags-include --version) >/dev/null 2>&1; then \
	  include_option=--etags-include; \
	  empty_fix=.; \
	else \
	  include_option=--include; \
	  empty_fix=; \
	fi; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    test ! -f $$subdir/TAGS || \
	      set "$$@" "$$include_option=$$here/$$subdir/TAGS"; \
	  fi; \
	done; \
	$(am__define_uniq_tagged_files); \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: ctags-recursive

CTAGS: ctags
ctags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	$(am__define_uniq_tagged_files); \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"
cscopelist: cscopelist-recursive

cscopelist-am: $(am__tagged_files)
	list='$(am__tagged_files)'; \
	case "$(srcdir)" in \
	  [\\/]* | ?:[\\/]*) sdir="$(srcdir)" ;; \
	  *) sdir=$(subdir)/$(srcdir) ;; \
	esac; \
	for i in $$list; do \
	  if test -f "$$i"; then \
	    echo "$(subdir)/$$i"; \
	  else \
	    echo "$$sdir/$$i"; \
	  fi; \
	done >> $(top_builddir)/cscope.files

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) distdir-am

distdir-am: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
	@list='$(DIST_SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    $(am__make_dryrun) \
	      || test -d "$(distdir)/$$subdir" \
	      || $(MKDIR_P) "$(distdir)/$$subdir" \
	      || exit 1; \
	    dir1=$$subdir; dir2="$(distdir)/$$subdir"; \
	    $(am__relativize); \
	    new_distdir=$$reldir; \
	    dir1=$$subdir; dir2="$(top_distdir)"; \
	    $(am__relativize); \
	    new_top_distdir=$$reldir; \
	    echo " (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) top_distdir="$$new_top_distdir" distdir="$$new_distdir" \\"; \
	    echo "     am__remove_distdir=: am__skip_length_check=: am__skip_mode_fix=: distdir)"; \
	    ($(am__cd) $$subdir && \
	      $(MAKE) $(AM_MAKEFLAGS) \
	        top_distdir="$$new_top_distdir" \
	        distdir="$$new_distdir" \
		am__remove_distdir=: \
		am__skip_length_check=: \
		am__skip_mode_fix=: \
	        distdir) \
	      || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-recursive
all-am: Makefile
installdirs: installdirs-recursive
installdirs-am:
install: install-recursive
install-exec: install-exec-recursive
install-data: install-data-recursive
uninstall: uninstall-recursive

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-recursive
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:
	-test -z "$(MOSTLYCLEANFILES)" || rm -f $(MOSTLYCLEANFILES)

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-recursive

clean-am: clean-generic clean-libtool mostlyclean-am

distclean: distclean-recursive
	-rm -f Makefile
distclean-am: clean-am distclean-generic distclean-tags

dvi: dvi-recursive

dvi-am:

html: html-recursive

html-am:

info: info-recursive

info-am:

install-data-am:

install-dvi: install-dvi-recursive

install-dvi-am:

install-exec-am:

install-html: install-html-recursive

install-html-am:

install-info: install-info-recursive

install-info-am:

install-man:

install-pdf: install-pdf-recursive

install-pdf-am:

install-ps: install-ps-recursive

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-recursive
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-recursive

mostlyclean-am: mostlyclean-generic mostlyclean-libtool

pdf: pdf-recursive

pdf-am:

ps: ps-recursive

ps-am:

uninstall-am:

.MAKE: $(am__recursive_targets) install-am install-strip

.PHONY: $(am__recursive_targets) CTAGS GTAGS TAGS all all-am check \
	check-am clean clean-generic clean-libtool cscopelist-am ctags \
	ctags-am distclean distclean-generic distclean-libtool \
	distclean-tags distdir dvi dvi-am html html-am info info-am \
	install install-am install-data install-data-am install-dvi \
	install-dvi-am install-exec install-exec-am install-html \
	install-html-am install-info install-info-am install-man \
	install-pdf install-pdf-am install-ps install-ps-am \
	install-strip installcheck installcheck-am installdirs \
	installdirs-am maintainer-clean maintainer-clean-generic \
	mostlyclean mostlyclean-generic mostlyclean-libtool pdf pdf-am \
	ps ps-am tags tags-am uninstall uninstall-am

.PRECIOUS: Makefile

.NOEXPORT:
M-y = $(M-objs)
obj-$(CONFIG_LUSTRE_FS) += M.o
