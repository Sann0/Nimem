import ../src/nimem
import os, random, strutils

when isMainModule:
  randomize()

  var 
    myValue: int = 100
    address = cast[ByteAddress](myValue.unsafeAddr)

  echo "Address of `myValue`: " & address.toHex(10)
  let p = processByName("example.exe")

  for _ in 1..5:
    echo "`myValue` holds: " & $p.read(address, int)
    sleep(1500)
    echo "randomizing `myValue`"
    myValue = rand(100000)

  p.close()