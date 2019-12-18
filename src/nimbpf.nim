import strutils
import posix
import tables
import options
import parseutils
import logging

import nimbpf/uapibpf
import nimbpf/libbpf

var logger = newConsoleLogger(useStderr=true)

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
    logger.log(lvlInfo, "uts.release=" & $release)
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
  r.rlim_cur = 200*1024*1024 # mb
  r.rlim_max = 200*1024*1024 # mb
  let res = setrlimit(RLIMIT_MEMLOCK, r)
  if res == 0:
    logger.log(lvlInfo, "set rlimit: success")
  else:
    logger.log(lvlWarn, "could not set rlimit")

proc checkKernelVersion(bpf_obj: ptr bpf_object): cuint =
  let kver: cuint = getKernelVersion()
  logger.log(lvlInfo, "kernel version detected = " & $kver)

  let elfkver: cuint = bpf_object_kversion(bpf_obj)
  if kver == elfkver:
    logger.log(lvlInfo, "  bpf object kernel version = " & $elfkver & " (match)")
  else:
    logger.log(lvlWarn, "  bpf object kernel version  = " & $elfkver & " (different, will overwrite)")
  return kver

proc bootBpf*(elfBpfFile: cstring): void =
  setRLimit()

  var bpf_obj = bpf_object_open(elfBpfFile)
  var name = bpf_object_name(bpf_obj)
  logger.log(lvlInfo, "bpf object opened: " & $name)

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
  logger.log(lvlInfo, "bpf loading:")
  let ret = bpf_object_load(bpf_obj)
  if ret == 0:
    logger.log(lvlInfo, "  bpf successfully loaded")
  else:
    logger.log(lvlError, "  bpf load failed: " & $ret) 

  # open fds for discovered maps
  logger.log(lvlInfo, "loading maps:")
  var bpf_map = bpf_map_next(nil, bpf_obj)
  while bpf_map != nil:
    let title = $(bpf_map_name(bpf_map))
    let fd = bpf_map_fd(bpf_map)
    if fd == -1:
      logger.log(lvlError, "  could not load map: " & title & "-" & $strerror(errno))
    else:
      mapFds[title] = fd
      logger.log(lvlInfo, "  loaded map: " & title)
    bpf_map = bpf_map_next(bpf_map, bpf_obj)

  # attach programs
  logger.log(lvlInfo, "attaching programs:")
  for _, prg in bpf_programs:
    let rawtitle = $bpf_program_title(prg, false)
    let title = rawtitle.split('/')
    case title[0]:
      of "kprobe":
        discard bpf_program_attach_kprobe(prg, false, title[1].cstring)
        logger.log(lvlInfo, "  program: " & rawtitle & " -> attached")
      of "kretprobe":
        discard bpf_program_attach_kprobe(prg, true, title[1].cstring)
        logger.log(lvlInfo, "  program: " & rawtitle & " -> attached")
      else:
        logger.log(lvlWarn, "  program: " & rawtitle & " -> unsupported")

proc openPinnedBpfMap*(map: string, filename: string): Option[uint64] =
  logger.log(lvlInfo, "opening pinned map from " & filename & " as " & map)
  let fd = bpf_obj_get(filename)
  if fd < 0:
    logger.log(lvlWarn, "  could not open map, bpf_obj_get returned: " & $fd)
    return none(uint64)

  # TODO the lengths of buffers here need some checking,
  # to be safe, make them shorter for the moment
  let buf = newString(4096)
  let buf_c_str: cstring = buf.cstring
  let fd_name = "/proc/self/fd/" & $fd
  let actually_read = readlink($fd_name, buf_c_str, 4096-1)
  if actually_read < 0:
    logger.log(lvlWarn, "  could not open map, readlink from fd " & $fd_name & " read: " & $actually_read)
    discard close(fd)
    return none(uint64)

  if actually_read >= 4090:
    logger.log(lvlWarn, "  could not open map, readlink from fd " & $fd_name & ": buffer too short")
    discard close(fd)
    return none(uint64)

  if not ($buf).contains("bpf-map"):
    logger.log(lvlWarn, "  could not open map, readlink did not return a bpf-map: " &
        $fd_name & " -> " & $buf)
    discard close(fd)
    return none(uint64)

  # TODO there are other types as well, but this is about bpf-map

  logger.log(lvlInfo, "  successfully opened bpf map with fd=" & $fd)
  mapFds[map] = fd

  # TODO how should the caller close the map?

  return some(fd.uint64)

proc fetchUint16FromMap*(map: string, key: var any): Option[uint16] =
  if not mapFds.hasKey(map):
    logger.log(lvlError, "fetchUint16FromMap: count not find fd for map (was bpf loaded?): " & $map)
    return none(uint16)

  var fd = mapFds[map]
  var value: cushort

  let ret = bpf_map_lookup_elem(fd, addr(key), addr(value))
  if ret == -1:
    return none(uint16)

  return some(value.uint16)


proc fetchUint64FromMap*(map: string, key: var any): Option[uint64] =
  if not mapFds.hasKey(map):
    logger.log(lvlError, "fetchUint64FromMap: count not find fd for map (was bpf loaded?): " & $map)
    return none(uint64)

  var fd = mapFds[map]
  var value: culonglong

  let ret = bpf_map_lookup_elem(fd, addr(key), addr(value))
  if ret == -1:
    return none(uint64)

  return some(value.uint64)

iterator getKeys*[T](map: string): T =
  if not mapFds.hasKey(map):
    logger.log(lvlError, "getKeys: count not find fd for map (was bpf loaded?): " & $map)
  else:
    var fd = mapFds[map]

    var prevkey: T
    var key: T

    var ret = bpf_map_get_next_key(fd, nil, addr(key))
    while ret == 0:
      yield key
      prevkey = key
      ret = bpf_map_get_next_key(fd, addr(prevkey), addr(key))

