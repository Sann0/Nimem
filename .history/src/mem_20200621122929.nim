import tables
import strformat
import strutils
import re

import winim/winstr
import winim/inc/[winbase, tlhelp32, windef, psapi]


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
    modules*: Table[string, Mod]a


proc pidInfo(pid: DWORD): Process =
  var snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
  defer: CloseHandle(snap)

  var me: MODULEENTRY32
  me.dwSize = sizeof(me).DWORD

  if Module32First(snap, addr me).bool:
    result = Process(
      name: $winstrConverterArrayToLPWSTR(me.szModule),
      pid: me.th32ProcessID,
      baseaddr: cast[ByteAddress](me.modBaseAddr),
      basesize: me.modBaseSize,
    )

    while Module32Next(snap, addr me).bool:
      var m = Mod(
        baseaddr: cast[ByteAddress](me.modBaseAddr),
        basesize: me.modBaseSize,
      )
      result.modules[$winstrConverterArrayToLPWSTR(me.szModule)] = m

proc ProcessByName*(name: string): Process =
  var pidArray = newSeq[int32](1024)
  var read: DWORD = 0

  assert EnumProcesses(pidArray[0].addr, 1024, read.addr).bool

  for i in 0..<int(int(read) / 4):
    var p = pidInfo(pidArray[i])
    if p.pid.bool and p.name == name:
      p.handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p.pid).DWORD
      if not p.handle.bool:
        raise newException(IOError, fmt"Unable to open Process [Pid: {p.pid}] [Error code: {GetLastError()}]")
      return p

  raise newException(IOError, fmt"Process '{name}' not found")

proc read*[T](p: Process, address: ByteAddress, t: typedesc[T]): T =
  if not ReadProcessMemory(
    p.handle, cast[pointer](address), cast[pointer](result.addr), cast[SIZE_T](sizeof(T)), nil
  ).bool:
    let
      err = GetLastError()
      errAddr = address.toHex()
    raise newException(
      AccessViolationError,
      fmt"Read failed [Address: 0x{errAddr}] [Error code: {err}]"
    )

proc readByteSeq*(p: Process, address: ByteAddress, size: SIZE_T): seq[byte] =
  var data = newSeq[byte](size)
  if not ReadProcessMemory(
    p.handle, cast[pointer](address), cast[pointer](data[0].addr), cast[SIZE_T](size), nil
  ).bool:
    let
      err = GetLastError()
      errAddr = address.toHex()
    raise newException(
      AccessViolationError,
      fmt"ReadByteSeq failed [Address: 0x{errAddr}] [Error code: {err}]"
    )
  result = data

proc readString*(p: Process, address: ByteAddress): string =
  let
    rb = p.read(address, array[0..150, byte])
    i = rb.find(0.byte)

  if i != -1:
    return cast[string](rb[0..<i])

  let errAddr = address.toHex()
  raise newException(
    AccessViolationError,
    fmt"ReadString failed [Address: 0x{errAddr}]"
  )

proc write*(p: Process, address: ByteAddress, data: any) =
  if not WriteProcessMemory(
    p.handle, cast[pointer](address), cast[pointer](data.unsafeAddr), cast[SIZE_T](sizeof(data)), nil
  ).bool:
    let
      err = GetLastError()
      errAddr = address.toHex()
    raise newException(
      AccessViolationError,
      fmt"Write failed [Address: 0x{errAddr}] [Error code: {err}]"
    )

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
    let byteString = cast[string](p.readByteSeq(cast[ByteAddress](mbi.BaseAddress), mbi.RegionSize)).toHex()
    VirtualProtectEx(p.handle, cast[LPCVOID](curAddr), mbi.RegionSize, oldProt, nil)

    let r = byteString.findBounds(rePattern)
    if r.first != -1:
      return r.first div 2 + curAddr

proc close*(p: Process): bool {.discardable.} =
  cast[bool](CloseHandle(p.handle))
