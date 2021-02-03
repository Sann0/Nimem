import ../src/nimem
import os, random, strutils

when isMainModule:
  randomize()

  var
    processName = splitPath(paramStr(0)).tail
    myValue: int = 100
    address = cast[ByteAddress](myValue.unsafeAddr)

  echo "Address of `myValue`: 0x" & address.toHex(10)
  let p = processByName(processName)

  for _ in 1..5:
    myValue = rand(1000)
    echo "randomized `myValue`: " & $myValue
    echo "reading `myValue`: " & $p.read(address, int)
    sleep(1500)

  p.close()