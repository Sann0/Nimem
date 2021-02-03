import ../src/nimem
import os, random, strutils

when isMainModule:
  randomize()

  var
    myValue: int
    processName = splitPath(paramStr(0)).tail
    address = cast[ByteAddress](myValue.unsafeAddr)

  echo "Address of `myValue`: 0x" & address.toHex(10)
  let p = processByName(processName)

  for _ in 1..5:
    var randValue = rand(1000)
    echo "writing `myValue`: " & $randValue
    p.write(address, randValue)
    echo "reading `myValue`: " & $p.read(address, int)
    sleep(1500)

  p.close()