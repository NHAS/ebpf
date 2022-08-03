//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I headers

type LPMtrieKey struct {

	// first member must be a prefix u32 wide
	// rest can are arbitrary
	Prefixlen uint32
	IP        net.IP
}

func (l LPMtrieKey) Bytes() []byte {
	output := make([]byte, 8)
	binary.LittleEndian.PutUint32(output[0:4], l.Prefixlen)
	copy(output[4:], l.IP.To4())

	return output
}

func (l *LPMtrieKey) Unpack(b []byte) error {
	if len(b) != 8 {
		return errors.New("Too short")
	}

	l.Prefixlen = binary.LittleEndian.Uint32(b[:4])
	l.IP = b[4:]

	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading spec: %s", err)
	}

	innerMapSpec := &ebpf.MapSpec{
		Name:      "inner_map",
		Type:      ebpf.LPMTrie,
		KeySize:   8, // 4 bytes for prefix, 4 bytes for u32 (ipv4)
		ValueSize: 1, // 1 byte for u8, quasi bool

		// This flag is required for dynamically sized inner maps.
		// Added in linux 5.10.
		Flags: unix.BPF_F_NO_PREALLOC,

		// We set this to 100 now, but this inner map spec gets copied
		// and altered later.
		MaxEntries: 1000,
	}

	spec.Maps["allowance_table"].InnerMap = innerMapSpec

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err = spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	for {

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Command (a)dd, (r)emove, (l)list: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		switch strings.TrimSpace(text) {
		case "l", "list":
			s, err := printMap(objs.AllowanceTable)
			if err != nil {
				log.Fatal("list", err)
			}
			log.Println(s)
		case "a", "add":
			fmt.Print("Bucket IP: ")
			bucket, _, err := askIp()
			if err != nil {
				fmt.Println("Not an ip address")
				continue
			}

			fmt.Print("IP dst: ")
			dest, mask, err := askIp()
			if err != nil {
				fmt.Println("Not an ip address")
				continue
			}

			var innerMapID ebpf.MapID
			err = objs.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
			if err != nil {
				if strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
					inner, err := ebpf.NewMap(innerMapSpec)
					if err != nil {
						log.Fatalf("create new map: %s", err)
					}
					defer inner.Close()

					err = objs.AllowanceTable.Put([]byte(bucket.To4()), uint32(inner.FD()))
					if err != nil {
						log.Fatalf("put outer: %s", err)
					}

					//Little bit clumbsy, but has to be done as there is no bpf_map_get_fd_by_id function in ebpf go style :P
					err = objs.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
					if err != nil {
						log.Fatalf("lookup inner: %s", err)
					}

				} else {
					log.Fatalf("lookup outer: %s", err)
				}
			}

			innerMap, err := ebpf.NewMapFromID(innerMapID)
			if err != nil {
				log.Fatalf("inner map: %s", err)
			}

			k := LPMtrieKey{Prefixlen: mask, IP: dest}

			err = innerMap.Put(k.Bytes(), uint8(1))
			if err != nil {
				log.Fatalf("inner map: %s", err)
			}

			innerMap.Close()

		case "r", "remove":
			fmt.Print("Bucket ip: ")
			bucket, _, err := askIp()
			if err != nil {
				fmt.Println("Not an ip address")
				continue
			}

			fmt.Print("Internal ip (or empty to remove bucket): ")
			target, mask, _ := askIp()

			if target != nil {
				var innerMapID ebpf.MapID
				err = objs.AllowanceTable.Lookup([]byte(bucket.To4()), &innerMapID)
				if err != nil {
					if strings.Contains(err.Error(), ebpf.ErrKeyNotExist.Error()) {
						log.Fatalf("lookup inner: %s", err)
					}
				}

				inner, err := ebpf.NewMapFromID(innerMapID)
				if err != nil {
					log.Fatalf("create new map: %s", err)
				}

				k := LPMtrieKey{Prefixlen: mask, IP: target}

				err = inner.Delete(k.Bytes())
				if err != nil {
					inner.Close()

					log.Println(err)
					continue
				}

				inner.Close()

				continue
			}

			err = objs.AllowanceTable.Delete([]byte(bucket.To4()))
			if err != nil {
				log.Println(err)
				continue
			}
		}

	}
}

func askIp() (net.IP, uint32, error) {
	reader := bufio.NewReader(os.Stdin)
	ipString, err := reader.ReadString('\n')
	if err != nil {
		return nil, 0, err
	}

	ipString = strings.TrimSpace(ipString)

	ip, netmask, err := net.ParseCIDR(ipString)
	if err != nil {
		out := net.ParseIP(ipString)
		if out != nil {
			return out, 32, nil
		}

		return nil, 0, errors.New("Could not parse ip from input")
	}

	ones, _ := netmask.Mask.Size()
	return ip, uint32(ones), nil
}

func printMap(m *ebpf.Map) (string, error) {
	var (
		sb         strings.Builder
		key        []byte
		innerMapID ebpf.MapID
	)

	iter := m.Iterate()
	sb.WriteString("\n")
	for iter.Next(&key, &innerMapID) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.

		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			log.Fatal("map from id: ", err)
		}

		sb.WriteString(fmt.Sprintf("%s:\n", sourceIP))

		var innerKey []byte
		var val uint8
		innerIter := innerMap.Iterate()
		kv := LPMtrieKey{}
		for innerIter.Next(&innerKey, &val) {
			kv.Unpack(innerKey)
			sb.WriteString(fmt.Sprintf("\t%s/%d\n", kv.IP, kv.Prefixlen))
		}
		innerMap.Close()

	}
	return sb.String(), iter.Err()
}
