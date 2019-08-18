[![Build Status](https://travis-ci.org/ba0f3/scram.nim.svg?branch=master)](https://travis-ci.org/ba0f3/scram.nim)

# scram
Salted Challenge Response Authentication Mechanism (SCRAM)


```nim
var s = newScramClient[Sha256Digest]()
s.clientNonce = "VeAOLsQ22fn/tjalHQIz7cQT"

echo s.prepareFirstMessage("bob")
let finalMessage = s.prepareFinalMessage("secret", "r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,s=ldZSefTzKxPNJhP73AmW/A==,i=4096")
echo finalMessage
assert(finalMessage == "c=biws,r=VeAOLsQ22fn/tjalHQIz7cQTmeE5qJh8qKEe8wALMut1,p=AtNtxGzsMA8evcWBM0MXFjxN8OcG1KRkLkFyoHlupOU=")
```
