import nimterop/cimport
import nimterop/git
import os

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
    checkout = "v0.0.7")

  cAddStdDir()
  cDisableCaching()

#  cskipSymbol @[
#    "bpf_insn",
#    "bpf_prog_info",
#    "xsk_socket_create",
#  ]

cImport(libbpfDir / "src/libbpf.h")
