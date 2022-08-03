# ebpf

Tiny little firewall showing how to use cilium ebpf with complex map types. 
Probably one of the only `BPF_MAP_TYPE_LPM_TRIE` examples on the internet. 

# Installation

```
sudo pacman -Syu llvm clang
BPF_CLANG=clang BPF_CFLAGS='-O2 -g -Wall -Werror' go generate
go build
```

# Maybe helpful?

```
sudo pacman -Syu libbpf linux-headers bpf 
```
