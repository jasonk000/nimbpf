headers=/usr/src/linux-headers-4.19.73netflix-g1d461644ed
cfile=ovfs.c
ofile=ovfs.o
build-elf:
	clang \
                -D__KERNEL__ \
                -D __BPF_TRACING__ \
                -emit-llvm \
                -O2 \
                -g \
                -c $(cfile) \
                -I $(headers)/include \
                -I $(headers)/arch/x86/include \
                -I $(headers)/arch/x86/include/generated \
                -I $(headers)/include/generated/uapi \
                -I $(headers)/arch/x86/include/uapi \
                -I $(headers)/include/uapi \
                -o - | \
                llc -march=bpf -filetype=obj -o $(ofile)

.PHONY: build-elf
