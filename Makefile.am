ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc

bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_nas_acl.la
COMMON_HARDEN_FLAGS=-fexceptions -fstack-protector-strong -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wall -Wformat -Wformat-security -Werror
C_HARDEN_FLAGS=-Wimplicit-function-declaration
LD_HARDEN_FLAGS=-Wl,-z,defs -Wl,-z,now

libopx_nas_acl_la_SOURCES= \
    src/nas_acl_init.cpp \
    src/nas_acl_table.cpp \
    src/nas_acl_cps_counter.cpp \
    src/nas_acl_counter.cpp \
    src/nas_acl_action.cpp \
    src/nas_acl_cps_stats.cpp \
    src/nas_acl_cps_action_map.cpp \
    src/nas_acl_entry.cpp \
    src/nas_acl_cps_filter.cpp \
    src/nas_acl_cps_utils.cpp \
    src/nas_acl_filter.cpp \
    src/nas_acl_switch.cpp \
    src/nas_acl_cps_action.cpp \
    src/nas_acl_cps_table.cpp \
    src/nas_acl_cps_filter_map.cpp \
    src/nas_acl_switch_list.cpp \
    src/nas_acl_utl.cpp \
    src/nas_acl_cps_entry.cpp \
    src/nas_acl_cps.cpp \
    src/nas_udf.cpp \
    src/nas_udf_cps_group.cpp \
    src/nas_udf_cps_match.cpp \
    src/nas_udf_cps_udf.cpp \
    src/nas_udf_group.cpp \
    src/nas_udf_match.cpp \
    src/nas_acl_cps_range.cpp \
    src/nas_acl_range.cpp \
    src/nas_acl_cps_acl_pool.cpp \
    src/nas_acl_cps_acl_profile.cpp

libopx_nas_acl_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(includedir)/opx $(COMMON_HARDEN_FLAGS) -fPIC
libopx_nas_acl_la_CXXFLAGS=-std=c++11
libopx_nas_acl_la_CFLAGS= $(C_HARDEN_FLAGS)
libopx_nas_acl_la_LDFLAGS=-shared -version-info 1:1:0 $(LD_HARDEN_FLAGS)
libopx_nas_acl_la_LIBADD=-lopx_common -lopx_nas_ndi -lopx_cps_api_common -lopx_logging -lopx_nas_linux -lopx_nas_common

systemdconfdir=/lib/systemd/system
systemdconf_DATA = scripts/init/*.service
