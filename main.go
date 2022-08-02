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
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

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

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
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
			s, err := printMap(objs.XdpStatsMap)
			if err != nil {
				log.Fatal(err)
			}
			log.Println(s)
		case "a", "add":
			ip, err := askIp()
			if err != nil {
				fmt.Println("Not an ip address")
				continue
			}

			err = objs.XdpStatsMap.Put([]byte(ip.To4()), uint8(1))
			if err != nil {
				log.Fatal(err)
			}
		case "r", "remove":
			ip, err := askIp()
			if err != nil {
				fmt.Println("Not an ip address")
				continue
			}

			err = objs.XdpStatsMap.Delete([]byte(ip.To4()))
			if err != nil {
				log.Fatal(err)
			}

		}

	}
}

func askIp() (net.IP, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter IP: ")
	ip, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	out := net.ParseIP(strings.TrimSpace(ip))
	if out == nil {
		return nil, errors.New("Could not parse ip from input")
	}

	return out, nil
}

func printMap(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val uint8
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.

		sb.WriteString(fmt.Sprintf("\t%s blocked\n", sourceIP))
	}
	return sb.String(), iter.Err()
}
