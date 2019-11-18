# nimbpf
libbpf for nim

## API

The API is simple, there are two calls available:

`proc bootBpf*(elfBpfFile: cstring): void`

This loads any maps and code available in the given file. The file should be
compiled along the lines of the instructions further along in this document.

`proc fetchFromMap*(map: string, key: var any): Option[uint64]`

This fetches a uint64 value from a BPF map. The map name should be a string
that matches the name in the bcc code. The key can be a pointer to any type
such as a culong or a normal nim object (aka struct). Obviously, it should
map to the same type as whatever bcc code was written.

### Teardown

When the process terminates, all BPF maps and probes will be destroyed by the
kernel.

## Defining a compatible ELF binary

_This should really be captured in a better place, nonetheless this will do
for now._

Use clang to compile an ELF binary containing the BPF IR. Include the struct
map sections so that the BPF maps can be automatically created.

- Create `bpf_helpers.h`, you can copy this straight from the project repo.
  This will include any relevant code and headers needed for your BCC
  compilation.

- Your BCC code. This should be basically the same as any existing BCC code,
  with a few specific pointers:
  - Declare any of the bpf maps you want instantiated in section "maps", and
    name them accordingly. `SEC` is defined in `bpf_helpers.h`
    ```
    SEC("maps")
    struct bpf_map_def ovfs_write_bytes = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(unsigned long),
        .max_entries = MAX_MAP_ENTRIES,
    };
    ```
  - Create the function code you need. Place the code in a section named as per
    the probe you want to attach them to.
    ```
    SEC("kprobe/ovl_read_iter")
    int trace_ovl_read_iter(struct pt_regs *ctx)
    {
        // bcc code
    }
    ```
  - You also need to include a `license` and a `version` section to tell the
    kernel what to load and ensure your code is compliant with kernel licensing
    process. Version section can be ignored as nimbpf will overwrite it for
    you even if it is incorrect.

- The Makefile, containing a single target to build your ELF binary. This will
  call clang, ask for `-emit-llvm`, include any required linux kernel headers,
  and pipe the output through `llc -march=bpf ..`
  ```
  headers=/usr/src/linux-headers
  build-elf:
        clang \
                -D__KERNEL__ \
                -D __BPF_TRACING__ \
                -emit-llvm \
                -O2 \
                -g \
                -c ovfs.c \
                -I $(headers)/include \
                -I $(headers)/arch/x86/include \
                -I $(headers)/arch/x86/include/generated \
                -I $(headers)/include/generated/uapi \
                -I $(headers)/arch/x86/include/uapi \
                -I $(headers)/include/uapi \
                -o - | \
                llc -march=bpf -filetype=obj -o ovfs.o
  .PHONY: build-elf
  ```

You should now have a working ELF file. Inspect it. Notice the:
- section headers, including your kprobe code, the relocation information for
  it (so that maps will be correctly fixed up), the maps, version, and license
  areas
- relocation section details including for each probe what maps are used

```
$ llvm-readelf-9 -a ovfs.o

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  ...
  [ 3] kprobe/ovl_read_iter PROGBITS     0000000000000000 000040 0000b8 00  AX  0   0  8
  [ 4] .relkprobe/ovl_read_iter REL      0000000000000000 019150 000020 10     31   3  8
  ...
  [11] maps              PROGBITS        0000000000000000 000de0 0000c4 00  WA  0   0  4
  [12] version           PROGBITS        0000000000000000 000ea4 000004 00  WA  0   0  4
  [13] license           PROGBITS        0000000000000000 000ea8 000004 00  WA  0   0  1

...

Relocation section '.relkprobe/ovl_read_iter' at offset 0x19150 contains 2 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name
0000000000000038  000006c200000001 R_BPF_64_64            0000000000000070 ovfs_op_start_times
0000000000000088  000006c200000001 R_BPF_64_64            0000000000000070 ovfs_op_start_times
```

You can see how your code disassembles to BPF IR (which is great for
debugging).

```
$ llvm-objdump-9 -S ovfs.o

ovfs.o:	file format ELF64-BPF


Disassembly of section kprobe/ovl_read_iter:

0000000000000000 trace_ovl_read_iter:
;     unsigned int pid = bpf_get_current_pid_tgid();
       0:	85 00 00 00 0e 00 00 00	call 14
       1:	63 0a f4 ff 00 00 00 00	*(u32 *)(r10 - 12) = r0
;     unsigned long ts = bpf_ktime_get_ns();
       2:	85 00 00 00 05 00 00 00	call 5
       3:	bf 06 00 00 00 00 00 00	r6 = r0
       4:	7b 6a f8 ff 00 00 00 00	*(u64 *)(r10 - 8) = r6
       5:	bf a2 00 00 00 00 00 00	r2 = r10
; int trace_ovl_read_iter(struct pt_regs *ctx)
       6:	07 02 00 00 f4 ff ff ff	r2 += -12
;     unsigned long *value = bpf_map_lookup_elem(map, key);
       7:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll

...

```

## TODO

- Attach to more than just kprobes. This should be pretty easy to extend.
- Probably there are more wrapper functions that we can create to support
  iteration, reading large maps, etc.
- Functions to delete and clear maps.

## Credits

Thanks to various developers of BPF and BCC bindings around, bpf, etc to show
the correct use of the API.
