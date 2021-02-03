import 
  os, tables, strutils,
  winim, regex
from strformat import fmt

type
  Module* = object
    baseaddr*: ByteAddress
    basesize*: int

  Process* = object
    name*: string
    handle*: int
    pid*: int32
    baseaddr*: ByteAddress
    basesize*: int
    modules*: Table[string, Module]

proc pidInfo(pid: int32): Process =
  var 
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
    me = MODULEENTRY32(dwSize: sizeof(MODULEENTRY32).cint)

  defer: CloseHandle(snap)

  if Module32First(snap, me.addr) == 1:
    result = Process(
      name: nullTerminated($$me.szModule),
      pid: me.th32ProcessID,
      baseaddr: cast[ByteAddress](me.modBaseAddr),
      basesize: me.modBaseSize,
    )

    result.modules[result.name] = Module(
      baseaddr: result.baseaddr,
      basesize: result.basesize,
    )

    while Module32Next(snap, me.addr) != 0:
      var m = Module(
        baseaddr: cast[ByteAddress](me.modBaseAddr),
        basesize: me.modBaseSize,
      )
      result.modules[nullTerminated($$me.szModule)] = m

proc processByName*(name: string): Process =
  var 
    pidArray = newSeq[int32](1024)
    read: int32

  assert EnumProcesses(pidArray[0].addr, 1024, read.addr) != FALSE

  for i in 0..<read div 4:
    var p = pidInfo(pidArray[i])
    if p.pid != 0 and name == p.name:
      p.handle = OpenProcess(PROCESS_ALL_ACCESS, 0, p.pid).int32
      if p.handle != 0:
        return p
      raise newException(Exception, fmt"Unable to open Process [Pid: {p.pid}] [Error code: {GetLastError()}]")
      
  raise newException(Exception, fmt"Process '{name}' not found")

iterator enumProcesses*: Process =
  var 
    pidArray = newSeq[int32](1024)
    read: int32

  assert EnumProcesses(pidArray[0].addr, 1024, read.addr) != FALSE

  for i in 0..<read div 4:
    var p = pidInfo(pidArray[i])
    if p.pid != 0: 
      yield p

proc waitForProcess*(name: string, interval: int = 1500): Process =
  while true:
    try:
      return process_by_name(name)
    except:
      sleep(interval)

proc close*(self: Process): bool {.discardable.} = 
  CloseHandle(self.handle) == 1

proc memoryErr(m: string, a: ByteAddress) {.inline.} =
  raise newException(
    AccessViolationDefect,
    fmt"{m} failed [Address: 0x{a.toHex()}] [Error: {GetLastError()}]"
  )

proc read*(self: Process, address: ByteAddress, t: typedesc): t =
  if ReadProcessMemory(
    self.handle, cast[pointer](address), result.addr, sizeof(t), nil
  ) == 0:
    memoryErr("Read", address)

proc write*(self: Process, address: ByteAddress, data: any) =
  if WriteProcessMemory(
    self.handle, cast[pointer](address), data.unsafeAddr, sizeof(data), nil
  ) == 0:
    memoryErr("Write", address)

proc writeArray*[T](self: Process, address: ByteAddress, data: openArray[T]) =
  if WriteProcessMemory(
    self.handle, cast[pointer](address), data.unsafeAddr, sizeof(T) * data.len, nil
  ) == 0:
    memoryErr("Write", address)

proc dmaAddr*(self: Process, baseAddr: ByteAddress, offsets: openArray[int]): ByteAddress =
  result = self.read(baseAddr, int32)
  for o in offsets:
    result = self.read(result + o, int32)

proc readSeq*(self: Process, address: ByteAddress, size: SIZE_T,  t: typedesc = byte): seq[t] =
  result = newSeq[t](size)
  if ReadProcessMemory(
    self.handle, cast[pointer](address), result[0].addr, size * sizeof(t), nil
  ) == 0:
    memoryErr("readSeq", address)

proc aobScan*(self: Process, pattern: string, module: Module = Module()): ByteAddress =
  var 
    scanBegin, scanEnd: int
    rePattern = re(
      pattern.toUpper().multiReplace((" ", ""), ("??", "?"), ("?", ".."), ("*", ".."))
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
  VirtualQueryEx(self.handle, cast[LPCVOID](scanBegin), mbi.addr, cast[SIZE_T](sizeof(mbi)))

  var curAddr = scanBegin
  while curAddr < scanEnd:
    curAddr += mbi.RegionSize.int
    VirtualQueryEx(self.handle, cast[LPCVOID](curAddr), mbi.addr, cast[SIZE_T](sizeof(mbi)))

    if mbi.State != MEM_COMMIT or mbi.State == PAGE_NOACCESS: continue

    var oldProt: int32
    VirtualProtectEx(self.handle, cast[LPCVOID](curAddr), mbi.RegionSize, PAGE_EXECUTE_READWRITE, oldProt.addr)
    let byteString = cast[string](self.readSeq(cast[ByteAddress](mbi.BaseAddress), mbi.RegionSize)).toHex()
    VirtualProtectEx(self.handle, cast[LPCVOID](curAddr), mbi.RegionSize, oldProt, nil)

    let r = byteString.findAllBounds(rePattern)
    if r.len != 0:
      return r[0].a div 2 + curAddr

proc nopCode*(self: Process, address: ByteAddress, length: int = 1) =
  var oldProt: int32
  discard VirtualProtectEx(self.handle, cast[LPCVOID](address), length, 0x40, oldProt.addr)
  for i in 0..length-1:
    self.write(address + i, 0x90.byte)
  discard VirtualProtectEx(self.handle, cast[LPCVOID](address), length, oldProt, nil)

proc patchBytes*(self: Process, address: ByteAddress, data: openArray[byte]) =
  var oldProt: int32
  discard VirtualProtectEx(self.handle, cast[LPCVOID](address), data.len, 0x40, oldProt.addr)
  for i, b in data:
    self.write(address + i, b)
  discard VirtualProtectEx(self.handle, cast[LPCVOID](address), data.len, oldProt, nil)

proc injectDll*(self: Process, dllPath: string) =
  let vPtr = VirtualAllocEx(self.handle, nil, dllPath.len(), MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE)
  WriteProcessMemory(self.handle, vPtr, dllPath[0].unsafeAddr, dllPath.len, nil)
  if CreateRemoteThread(self.handle, nil, 0, cast[LPTHREAD_START_ROUTINE](LoadLibraryA), vPtr, 0, nil) == 0:
    raise newException(Exception, fmt"Injection failed [Error: {GetLastError()}]")

proc pageProtection*(self: Process, address: ByteAddress, newProtection: int32 = 0x40): int32  =
  var mbi = MEMORY_BASIC_INFORMATION()
  discard VirtualQueryEx(self.handle, cast[LPCVOID](address), mbi.addr, cast[SIZE_T](sizeof(mbi)))
  discard VirtualProtectEx(self.handle, cast[LPCVOID](address), mbi.RegionSize, newProtection, result.addr)

proc readString*(self: Process, address: ByteAddress): string =
  let r = self.read(address, array[0..100, char])
  $cast[cstring](r[0].unsafeAddr)