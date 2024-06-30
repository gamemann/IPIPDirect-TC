CC = clang

BUILD_DIR = build
SRC_DIR = src

LIBBPF_DIR = $(SRC_DIR)/include/libbpf
LIBBPF_STATIC_DIR = $(LIBBPF_DIR)/src/staticobjs

LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/bpf_prog_linfo.o $(LIBBPF_STATIC_DIR)/bpf.o $(LIBBPF_STATIC_DIR)/btf_dump.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/btf_iter.o $(LIBBPF_STATIC_DIR)/btf_relocate.o $(LIBBPF_STATIC_DIR)/btf.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/elf.o $(LIBBPF_STATIC_DIR)/features.o $(LIBBPF_STATIC_DIR)/gen_loader.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/hashmap.o $(LIBBPF_STATIC_DIR)/libbpf_errno.o $(LIBBPF_STATIC_DIR)/libbpf_probes.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/libbpf.o $(LIBBPF_STATIC_DIR)/linker.o $(LIBBPF_STATIC_DIR)/netlink.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/nlattr.o $(LIBBPF_STATIC_DIR)/relo_core.o $(LIBBPF_STATIC_DIR)/ringbuf.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/str_error.o $(LIBBPF_STATIC_DIR)/strset.o $(LIBBPF_STATIC_DIR)/usdt.o
LIBBPF_STATIC_OBJS += $(LIBBPF_STATIC_DIR)/zip.o

CFLAGS += -I$(LIBBPF_DIR)/src -g -O2

all: loader kern
kern:
	$(CC) -O2 --target=bpf -g -c $(SRC_DIR)/IPIPDirect_kern.c -o $(BUILD_DIR)/IPIPDirect_filter.o
loader: libbpf
	$(CC) -lelf -lz -o $(BUILD_DIR)/IPIPDirect_loader $(LIBBPF_STATIC_OBJS) $(SRC_DIR)/IPIPDirect_loader.c
clean:
	$(MAKE) -C $(LIBBPF_DIR)/src clean
	rm -f $(BUILD_DIR)/*.o
	rm -f $(BUILD_DIR)/*.bc
	rm -f $(BUILD_DIR)/IPIPDirect_loader
libbpf:
	$(MAKE) -C $(LIBBPF_DIR)/src
install:
	mkdir -p /etc/IPIPDirect/
	cp $(BUILD_DIR)/IPIPDirect_filter.o /etc/IPIPDirect/IPIPDirect_filter.o
	cp $(BUILD_DIR)/IPIPDirect_loader /usr/bin/IPIPDirect_loader
	cp -n other/IPIPDirect.service /etc/systemd/system/IPIPDirect.service
.PHONY: libbpf all
.DEFAULT: all