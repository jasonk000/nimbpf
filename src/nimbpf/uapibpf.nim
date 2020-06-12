import nimterop/cimport
import nimterop/git
import os

const
  srcDir = currentSourcePath.parentDir()
  libbpfDir = srcDir / "build/libbpf"

static: cDisableCaching()

static: gitPull( 
  "https://github.com/libbpf/libbpf.git",
  outdir = libbpfDir,
  #checkout = "7e447c35b7b83351c630a5c09cb802d19e4bcacc")
  #checkout = "0a216f37f8f4aaa9c466ce5320ec751c1de1e4ab")
  )

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

  type bpf_prog_info* {.importc: "struct bpf_prog_info", bycopy.} = object
    `type`*: u32
    id*: u32
    tag*: array[8, u8]
    jited_prog_len*: u32
    xlated_prog_len*: u32
    jited_prog_insns*: u64
    xlated_prog_insns*: u64
    load_time*: u64
    created_by_uid*: u32
    nr_map_ids*: u32
    map_ids*: u64
    name*: array[16U, cchar]
    ifindex*: u32
    gpl_compatible* {.bitsize: 1.} : u32
    netns_dev*: u64
    netns_ino*: u64
    nr_jited_ksyms*: u32
    nr_jited_func_lens*: u32
    jited_ksyms*: u64
    jited_func_lens*: u64
    btf_id*: u32
    func_info_rec_size*: u32
    func_info*: u64
    nr_func_info*: u32
    nr_line_info*: u32
    line_info*: u64
    jited_line_info*: u64
    nr_jited_line_info*: u32
    line_info_rec_size*: u32
    jited_line_info_rec_size*: u32
    nr_prog_tags*: u32
    prog_tags*: u64
    run_time_ns*: u64
    run_cnt*: u64
  type bpf_map_info* {.importc: "struct bpf_map_info", bycopy.} = object
    `type`*: u32
    id*: u32
    key_size*: u32
    value_size*: u32
    max_entries*: u32
    map_flags*: u32
    name*: array[16U, cchar]
    ifindex*: u32
    `32`*: u32
    netns_dev*: u64
    netns_ino*: u64
    btf_id*: u32
    btf_key_type_id*: u32
    btf_value_type_id*: u32


static: cskipSymbol @[
  # nimterop cannot yet deal with a complex enum chain
  "__LIBBPF_ERRNO__START",
  # defined in perf which we do not need
  "perf_buffer_raw_opts",
  "perf_buffer__new_raw",
  # stuff we do not need yet
  "bpf_func_id",
  "bpf_probe_helper",
  "bpf_prog_info_linear",
  "bpf_program__get_prog_info_linear",
  "bpf_program__bpil_addr_to_offs",
  "bpf_program__bpil_offs_to_addr",
  "bpf_map_def",
  "bpf_map_info",
  "bpf_prog_info",
]

cImport(libbpfDir / "include/uapi/linux/bpf.h")
