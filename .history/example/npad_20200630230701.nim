#[
  Read input from notepad.exe
]#

import nimem

import os
import sequtils

const CharOffset = 0x2C470

proc parseTextArray(a: openArray[byte]): string =
  let 
    s = toSeq(a.pairs)
      .filterIt(it[0] mod 2 == 0)
      .mapIt(it[1])
    i = s.find(0.byte)

  cast[string](s[0..<i])

when isMainModule:
  try:
    let 
      p = ProcessByName("notepad.exe")
      txtPtr = p.dmaAddr(p.baseaddr + CharOffset, [0x0])

    while true:
      echo parseTextArray(
        p.read(txtPtr, array[500, byte])
      )
      sleep(200)
      discard os.execShellCmd("cls")
  except:
    echo "Error: " & getCurrentExceptionMsg()