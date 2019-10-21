import strutils
import posix
import tables
import options
import parseutils

import nimbpf/uapibpf
import nimbpf/libbpf

var mapFds = initTable[string, cint]()

proc getKernelVersion(): cuint =
  # only tested on ubuntu
  var f: File
  var line: string
  if open(f, "/proc/version_signature"):
    if f.readLine(line):
      let versiontag = line.split(' ')[2].split('.')
      let major = parseUInt(versiontag[0])
      let minor = parseUInt(versiontag[1])
      let patch = parseUInt(versiontag[2])
      return ((major shl 16) + (minor shl 8) + patch).cuint

  var uts: Utsname
  if posix.uname(uts) == 0:
    var release: string = ""
    for c in uts.release:
      if c != '\x00':
        release = release & $(c)
    # logInfo("uts.release=" & $release)
    let versiontag = release.split('-')[0].split('.')
    let major = parseUInt(versiontag[0])
    let minor = parseUInt(versiontag[1])
    var patchstr: string
    discard versiontag[2].parseWhile(patchstr, Digits)
    let patch = parseUInt(patchstr)
    return ((major shl 16) + (minor shl 8) + patch).cuint

  return 0

proc setRLimit(): void =
  const RLIMIT_MEMLOCK = 8 # ugh, see resource.h
  var r: RLimit
  r.rlim_cur = 100*1024*1024 # 100mb
  r.rlim_max = 100*1024*1024 # 100mb
  let res = setrlimit(RLIMIT_MEMLOCK, r)
  if res == 0:
    # logInfo("set rlimit: success")
  else:
    # logWarning("could not set rlimit")

proc checkKernelVersion(bpf_obj: ptr bpf_object): cuint =
  let kver: cuint = getKernelVersion()
  # logInfo("kernel version detected = " & $kver)

  let elfkver: cuint = bpf_object_kversion(bpf_obj)
  if kver == elfkver:
    # logInfo("  bpf object kernel version = " & $elfkver & " (match)")
  else:
    # logWarning("  bpf object kernel version  = " & $elfkver & " (different, will overwrite)")
  return kver

proc bootBpf*(elfBpfFile: cstring): void =
  setRLimit()

  var bpf_obj = bpf_object_open(elfBpfFile)
  var name = bpf_object_name(bpf_obj)
  # logInfo("bpf object opened: " & $name)

  let kver = checkKernelVersion(bpf_obj)
  bpf_object_set_kversion(bpf_obj, kver)

  # set up configuration for programs to load
  var bpf_programs: seq[ptr bpf_program] = @[]
  var bpf_prg = bpf_program_next(nil, bpf_obj)
  while bpf_prg != nil:
    bpf_programs.add(bpf_prg)
    bpf_prg = bpf_program_next(bpf_prg, bpf_obj)

  for prg in bpf_programs:
    let rawtitle = $bpf_program_title(prg, false)
    bpf_program_set_type(prg, BPF_PROG_TYPE_KPROBE)
    bpf_program_set_expected_attach_type(prg, MAX_BPF_ATTACH_TYPE)

  # do the load
  # logInfo("bpf loading:")
  let ret = bpf_object_load(bpf_obj)
  if ret == 0:
    # logInfo("  bpf successfully loaded")
  else:
    # logErr("  bpf load failed: " & $ret) 

  # open fds for discovered maps
  # logInfo("loading maps:")
  var bpf_map = bpf_map_next(nil, bpf_obj)
  while bpf_map != nil:
    let title = $(bpf_map_name(bpf_map))
    let fd = bpf_map_fd(bpf_map)
    if fd == -1:
      # logErr("  could not load map: " & title & "-" & $strerror(errno))
    else:
      mapFds[title] = fd
      # logInfo("  loaded map: " & title)
    bpf_map = bpf_map_next(bpf_map, bpf_obj)

  # attach programs
  # logInfo("attaching programs:")
  for _, prg in bpf_programs:
    let rawtitle = $bpf_program_title(prg, false)
    let title = rawtitle.split('/')
    case title[0]:
      of "kprobe":
        discard bpf_program_attach_kprobe(prg, false, title[1].cstring)
        # logInfo("  program: " & rawtitle & " -> attached")
      of "kretprobe":
        discard bpf_program_attach_kprobe(prg, true, title[1].cstring)
        # logInfo("  program: " & rawtitle & " -> attached")
      else:
        # logWarning("  program: " & rawtitle & " -> unsupported")

proc fetchFromContainerMap*(map: string, container: string): Option[uint64] =
  if not mapFds.hasKey(map):
    # logErr("fetchFromContainerMap: count not find fd for map (was bpf loaded?): " & $map)
    return none(uint64)

  var key = containerNameToPidNs(container)
  if key.isNone():
    # logWarning("fetchFromContainerMap: could not find pidns for: " & $container)
    return none(uint64)

  var value: culonglong
  var fd = mapFds[map]
  let ret = bpf_map_lookup_elem(fd, addr(key), addr(value))
  if ret == -1:
    # logWarning("fetchFromContainerMap: did not find value in map for: " & $container)
    return none(uint64)

  return some(value.uint64)
