CC = clang

objects += src/IPIPDirect_loader.o

libbpf_static_objects += src/include/libbpf/src/staticobjs/bpf.o src/include/libbpf/src/staticobjs/btf.o src/include/libbpf/src/staticobjs/libbpf_errno.o src/include/libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += src/include/libbpf/src/staticobjs/libbpf.o src/include/libbpf/src/staticobjs/netlink.o src/include/libbpf/src/staticobjs/nlattr.o src/include/libbpf/src/staticobjs/str_error.o
libbpf_static_objects += src/include/libbpf/src/staticobjs/hashmap.o src/include/libbpf/src/staticobjs/bpf_prog_linfo.o 

libbpf_shared_objects += src/include/libbpf/src/sharedobjs/bpf.o src/include/libbpf/src/sharedobjs/btf.o src/include/libbpf/src/sharedobjs/libbpf_errno.o src/include/libbpf/src/sharedobjs/libbpf_probes.o
libbpf_shared_objects += src/include/libbpf/src/sharedobjs/libbpf.o src/include/libbpf/src/sharedobjs/netlink.o src/include/libbpf/src/sharedobjs/nlattr.o src/include/libbpf/src/sharedobjs/str_error.o

CFLAGS += -Isrc/include/libbpf/src -g -O2 -Wall -Werror

all: loader kern
kern:
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/IPIPDirect_kern.c -o src/IPIPDirect_kern.bc
	llc -march=bpf -filetype=obj src/IPIPDirect_kern.bc -o src/IPIPDirect_filter.o 
loader: libbpf $(objects)
	clang -lelf -lz -o src/IPIPDirect_loader $(libbpf_static_objects) $(objects)
clean:
	$(MAKE) -C src/include/libbpf/src clean
	rm -f src/*.o
	rm -f src/*.bc
	rm -f src/IPIPDirect_loader
libbpf:
	$(MAKE) -C src/include/libbpf/src
install:
	mkdir -p /etc/IPIPDirect/
	cp src/IPIPDirect_filter.o /etc/IPIPDirect/IPIPDirect_filter.o
	cp src/IPIPDirect_loader /usr/bin/IPIPDirect_loader
	cp -n other/IPIPDirect.service /etc/systemd/system/IPIPDirect.service
.PHONY: libbpf all
.DEFAULT: all