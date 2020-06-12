import nimterop/cimport
import nimterop/git
import os

import uapibpf 

const LIBBPF_H_PATCH = """
void bpf_object__set_kversion(struct bpf_object *obj, unsigned int kern_version);
"""

const LIBBPF_C_PATCH = """
void bpf_object__set_kversion(struct bpf_object *obj, unsigned int kern_version)
{
    obj->kern_version = kern_version;
}
"""

const
  srcDir = currentSourcePath.parentDir()
  libbpfDir = srcDir / "build/libbpf"

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'})
    sym.name = sym.name.replace("__", "_")

cOverride:
  const LIBBPF_ERRNO_LIBELF* = 4001

  type u8 {.size:sizeof(int8).} = cuint
  type u32 {.size:sizeof(int32).} = cuint
  type u64 {.size:sizeof(int64).} = cuint
  type s16 {.size:sizeof(int16).} = cint
  type s32 {.size:sizeof(int32).} = cint
  type pid_t = cuint

static:
  gitPull( 
    "https://github.com/libbpf/libbpf.git",
    outdir = libbpfDir,
    #checkout = "7e447c35b7b83351c630a5c09cb802d19e4bcacc")
    #checkout = "0a216f37f8f4aaa9c466ce5320ec751c1de1e4ab")
    )

  # this is a little cheeky, but saves a lot of implementation effort
  # libbpf does not provide a set_kversion to set the version of the ELF file,
  # but kernel < 5.0 requires an exact match in kversion (5.x+ dropped this)
  #
  # the alternatives:
  # - parse the elf file section by section, applying relocs manually so that
  #   we can also pass our intended kversion at the right point
  # - recompile the ELF file each time including the version (defeating the purpose)
  # - patch the ELF file on the host (also seems feasible)
  #let beforec = readFile(libbpfDir / "src/libbpf.c")
  #writeFile(libbpfDir / "src/libbpf.c", beforec & LIBBPF_C_PATCH)

  #let beforeh = readFile(libbpfDir / "src/libbpf.h")
  #writeFile(libbpfDir / "src/libbpf.h", beforeh & LIBBPF_H_PATCH)

  #cAddStdDir()
  cDisableCaching()

  make(libbpfDir / "src", "libbpf.so")

  cskipSymbol @[
    "bpf_insn",
    "bpf_prog_info",
    "xsk_socket_create",
  ]

cIncludeDir(libbpfDir / "include")
cIncludeDir(libbpfDir / "include/uapi")
cCompile(libbpfDir / "src/*.c")
cImport(libbpfDir / "src/libbpf.h")
cImport(libbpfDir / "src/bpf.h")
