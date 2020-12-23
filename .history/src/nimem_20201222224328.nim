import tables, re, os
import strformat, strutils

import winim/winstr
import winim/inc/[winbase, tlhelp32, windef, psapi]

const NOP = 0x90.byte

type
  Mod* = object
    baseaddr*: ByteAddress
    basesize*: DWORD

  Process* = object
    name*: string
    handle*: HANDLE
    pid*: DWORD
    baseaddr*: ByteAddress
    basesize*: DWORD
    modules*: Table[string, Mod]

proc memoryErr(m: string, a: ByteAddress) =
  raise newException(
    AccessViolationDefect,
    fmt"{m} failed [Address: 0x{a.toHex()}] [Error: {GetLastError()}]"
  )

proc pidInfo(pid: DWORD): Process =
  var snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
  defer: CloseHandle(snap)

  var me = MODULEENTRY32(dwSize: sizeof(MODULEENTRY32).cint)

  if Module32First(snap, me.addr) == 1:
    result = Process(
      name: cast[string](me.szModule[0].unsafeAddr),
      pid: me.th32ProcessID,
      baseaddr: cast[ByteAddress](me.modBaseAddr),
      basesize: me.modBaseSize,
    )

    result.modules[result.name] = Mod(
      baseaddr: result.baseaddr,
      basesize: result.basesize,
    )

    while Module32Next(snap, me.addr) != 0:
      var m = Mod(
        baseaddr: cast[ByteAddress](me.modBaseAddr),
        basesize: me.modBaseSize,
      )
      result.modules[$winstrConverterArrayToLPWSTR(me.szModule)] = m

proc processByName*(name: string): Process =
  var pidArray = newSeq[int32](1024)
  var read: DWORD

  assert EnumProcesses(pidArray[0].addr, 1024, read.addr) != FALSE

  for i in 0..<read div 4:
    var p = pidInfo(pidArray[i])
    if p.pid != 0 and p.name == name:
      p.handle = OpenProcess(PROCESS_ALL_ACCESS, 0, p.pid).DWORD
      if p.handle != 0:
        return p
      raise newException(IOError, fmt"Unable to open Process [Pid: {p.pid}] [Error code: {GetLastError()}]")
      
  raise newException(IOError, fmt"Process '{name}' not found")

proc waitForProcess*(name: string, interval = 1500): Process =
  while true:
    try:
      result = processByName(name)
      break
    except:
      sleep(interval)

proc read*(p: Process, address: ByteAddress, t: typedesc): t =
  if ReadProcessMemory(
    p.handle, cast[pointer](address), result.addr, cast[SIZE_T](sizeof(t)), nil
  ) == 0:
    memoryErr("Read", address)

proc readSeq*(p: Process, address: ByteAddress, size: SIZE_T,  t: typedesc = byte): seq[t] =
  result = newSeq[t](size)
  if ReadProcessMemory(
    p.handle, cast[pointer](address), result[0].addr, size, nil
  ) == 0:
    memoryErr("readSeq", address)

proc readString*(p: Process, address: ByteAddress): string =
  let r = p.read(address, array[0..150, char])
  result = $cast[cstring](r[0].unsafeAddr)

proc write*(p: Process, address: ByteAddress, data: any) =
  if WriteProcessMemory(
    p.handle, cast[pointer](address), data.unsafeAddr, cast[SIZE_T](sizeof(data)), nil
  ) == 0:
    memoryErr("Write", address)

proc dmaAddr*(p: Process, baseAddr: ByteAddress, offsets: openArray[int]): ByteAddress =
  result = p.read(baseAddr, ByteAddress)
  for o in offsets:
    inc result, o
    result = p.read(result, ByteAddress)

proc aobScan*(p: Process, pattern: string, module: Mod = Mod()): ByteAddress =
  var scanBegin, scanEnd: int
  var rePattern = re(
    pattern.toUpper().multiReplace((" ", ""), ("?", ".."), ("*", "..")),
    {reIgnoreCase, reDotAll}
  )

  if module.baseaddr != 0:
    scanBegin = module.baseaddr
    scanEnd = module.baseaddr + module.basesize
  else:
    var sysInfo = SYSTEM_INFO()
    GetSystemInfo(sysInfo.addr)
    scanBegin = cast[int](sysInfo.lpMinimumApplicationAddress)
    scanEnd = cast[int](sysInfo.lpMaximumApplicationAddress)

  var mbi = MEMORY_BASIC_INFORMATION()
  VirtualQueryEx(p.handle, cast[LPCVOID](scanBegin), mbi.addr, cast[SIZE_T](sizeof(mbi)))

  var curAddr = scanBegin
  while curAddr < scanEnd:
    curAddr += mbi.RegionSize.int
    VirtualQueryEx(p.handle, cast[LPCVOID](curAddr), mbi.addr, cast[SIZE_T](sizeof(mbi)))

    if mbi.State != MEM_COMMIT or mbi.State == PAGE_NOACCESS: continue

    var oldProt: DWORD
    VirtualProtectEx(p.handle, cast[LPCVOID](curAddr), mbi.RegionSize, PAGE_EXECUTE_READWRITE, oldProt.addr)
    let byteString = cast[string](p.readSeq(cast[ByteAddress](mbi.BaseAddress), mbi.RegionSize)).toHex()
    VirtualProtectEx(p.handle, cast[LPCVOID](curAddr), mbi.RegionSize, oldProt, nil)

    let r = byteString.findBounds(rePattern)
    if r.first != -1:
      return r.first div 2 + curAddr

proc nopCode*(p: Process, address: ByteAddress, length: int = 1) =
  for i in 0..length-1:
    p.write(address + i, NOP)

proc close*(p: Process): bool {.discardable.} = CloseHandle(p.handle) == 1
