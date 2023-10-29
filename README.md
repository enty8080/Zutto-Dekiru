# Zutto Dekiru

Zutto Dekiru is a native HatSploit encoder that represents a XOR encoded shellcode with automatically generated decoder with dynamically selected registers and FPU instructions. 

## Usage

In HatSploit Framework Zutto Dekiru encoder can be selected using `set encoder` command. Zutto Dekiru should be used in chain with payloads, so modules will be able to encode it and send to the target.

```
set encoder x64/zutto_dekiru
```
