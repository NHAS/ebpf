# ebpf


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
