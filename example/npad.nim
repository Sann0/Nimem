#[
  Read input from notepad.exe
]#

import nimem

import os
import sequtils

const CharOffset = 0x2C470

proc parseTextArray(a: openArray[byte]): cstring =
  let 
    s = toSeq(a.pairs)
      .filterIt(it[0] mod 2 == 0)
      .mapIt(it[1])
      
  result = cast[cstring](s[0].unsafeAddr)

when isMainModule:
  try:
    let 
      p = processByName("notepad.exe")
      txtPtr = p.dmaAddr(p.baseaddr + CharOffset, [0x0])

    while true:
      echo parseTextArray(
        p.read(txtPtr, array[500, byte])
      )
      sleep(200)
      discard os.execShellCmd("cls")
  except:
    echo "Error: " & getCurrentExceptionMsg()