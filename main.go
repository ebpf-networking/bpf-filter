package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
)

const MAXLEN = 2000

// ifindex,mac address mapping for the interfaces
type entryMacMap struct {
	ifIdx uint32
	mac   net.HardwareAddr
}

// ifindex,mac address mapping for the interfaces
type entryIpMap struct {
	ifIdx uint32
	ip    net.IP
}

// cntPkt resembles cntPkt in ebpf kernel code
type cntPkt struct {
	drop uint32
	pass uint32
}

type statEntry struct {
	ifIdx uint32
	count cntPkt
}

func initializeStatsMap(m *ebpf.Map, entries []uint32) error {
	fmt.Printf("initStatsMap : Info: %v keysize: %v valueSize: %v\n", m.String(), m.KeySize(), m.ValueSize())
	for _, entry := range entries {
		cntPkt := cntPkt{drop: 0, pass: 0}
		err := m.Put(entry, (cntPkt))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

func makeMACEntry(ifIdx uint32, mac net.HardwareAddr) *entryMacMap {
	var en entryMacMap
	en.ifIdx = ifIdx
	en.mac = mac
	fmt.Printf("created an entry with id %d, mac %s\n", ifIdx, mac)
	return &en
}

func makeIPEntry(ifIdx uint32, ip net.IP) *entryIpMap {
	var en entryIpMap
	en.ifIdx = ifIdx
	en.ip = ip
	fmt.Printf("created an entry with id %d, ip %s\n", ifIdx, ip)
	return &en
}

func getInterface(idx int) (*net.Interface, error) {
	ifa, err := net.InterfaceByIndex(idx)
	if err != nil {
		fmt.Printf("Error: %v\n", err.Error())
		return nil, err
	}
	return ifa, nil
}

// This will overwrite previous entry if any
func addEntryMacMap(m *ebpf.Map, entries []entryMacMap, rand int) error {
	for _, ifa := range entries {
		err := m.Put(ifa.ifIdx+uint32(rand), []byte(ifa.mac))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

// This will overwrite previous entry if any
func addEntryIpMap(m *ebpf.Map, entries []entryIpMap, rand int) error {
	for _, ifa := range entries {
		ipadr, ok := netip.AddrFromSlice([]byte(ifa.ip))
		if !ok {
			fmt.Printf("Error ip conv")
			return nil
		}
		ipnum := ipadr.As4()
		err := m.Put(ifa.ifIdx+uint32(rand), ipnum)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

// This will ignore missing entries and always return success
func delEntryMap(m *ebpf.Map, keys []interface{}) error {
	for _, ifa := range keys {
		var err error
		switch ifa.(type) {
		case uint32:
			err = m.Delete(ifa.(uint32))
		case string:
			err = m.Delete(ifa.(string))
		}
		fmt.Printf("[delMap] ifIdx: %v\n", ifa)
		if err != nil {
			fmt.Printf("[delMap] Warn: %v\n", err)
		}
	}
	return nil
}

func createArray(maxEntries int, keySize int, valueSize int) (*ebpf.Map, error) {
	fmt.Printf("KeySize: %d ValueSize: %d MaxEntries: %d\n", keySize, valueSize, maxEntries)
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(keySize),
		ValueSize:  uint32(valueSize),
		MaxEntries: uint32(maxEntries),
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func pinMap(m *ebpf.Map, path string) error {
	if err := m.Pin(path); err != nil {
		m.Close()
		//fmt.Printf("[pinMap] Error! pin map: %s\n", err)
		return err
	}
	return nil
}

func closeMap(m *ebpf.Map) error {
	return m.Close()
}

func getMap(path string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(path)
}

func pinOrGetMap(path string, m *ebpf.Map) (*ebpf.Map, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err = pinMap(m, path)
		if err != nil {
			return m, err
		}
		return m, nil
	} else {
		temp, err := getMap(path)
		if err != nil {
			return m, err
		}
		return temp, nil
	}
}

func main() {

	var mode string
	var idx int
	var arg_mac string
	var arg_ip string

	flag.StringVar(&mode, "mode", "invalid", "Mode can be add")
	flag.IntVar(&idx, "idx", 0, "iface index where tc hook is attached")
	flag.StringVar(&arg_mac, "mac", "invalid", "MAC address which is allowed to pass through idx")
	flag.StringVar(&arg_ip, "ip", "invalid", "IP address which is allowed to pass through idx")

	flag.Parse()
	fmt.Printf("Mode: %v idx: %v", mode, idx)

	mapPathDir := "/sys/fs/bpf/tc/globals/"

	ifaceMacMapPath := "/sys/fs/bpf/tc/globals/iface_map"
	ifaceIpMapPath := "/sys/fs/bpf/tc/globals/iface_ip_map"
	egressCountMapPath := "/sys/fs/bpf/tc/globals/egress_iface_stat_map"
	ingressCountMapPath := "/sys/fs/bpf/tc/globals/ingress_iface_stat_map"

	var mac_map *ebpf.Map
	var ip_map *ebpf.Map
	var m *ebpf.Map
	var ingress_stats_map *ebpf.Map
	var egress_stats_map *ebpf.Map

	var en entryMacMap
	var ct cntPkt

	err := os.MkdirAll(mapPathDir, os.ModePerm)
	if err != nil {
		fmt.Printf("Error while creating the directory %s\n", err)
		return
	}

	mac_map, err = pinOrGetMap(ifaceMacMapPath, mac_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	ip_map, err = pinOrGetMap(ifaceIpMapPath, ip_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	egress_stats_map, err = createArray(MAXLEN, int(unsafe.Sizeof(en.ifIdx)), int(unsafe.Sizeof(ct)))
	egress_stats_map, err = pinOrGetMap(egressCountMapPath, egress_stats_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	ingress_stats_map, err = createArray(MAXLEN, int(unsafe.Sizeof(en.ifIdx)), int(unsafe.Sizeof(ct)))
	ingress_stats_map, err = pinOrGetMap(ingressCountMapPath, ingress_stats_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	switch mode {
	case "add":
		ifa, err := getInterface(idx)
		if err != nil {
			fmt.Printf("Could not get interface %v\n", err.Error())
			os.Exit(1)
		}
		entries := []entryMacMap{}

		hwa, err := net.ParseMAC(arg_mac)
		if err != nil {
			hwa = ifa.HardwareAddr
		}
		e := makeMACEntry(uint32(ifa.Index), hwa)
		entries = append(entries, *e)
		err = addEntryMacMap(mac_map, entries, 0)
		if err != nil {
			fmt.Printf("Error! populating mac map: %s\n", err)
			return
		}

		ip := net.ParseIP((arg_ip))
		if ip == nil {
			fmt.Printf("Error parsing ip\n")
			return
		}

		ip_entries := []entryIpMap{}
		ip_entry := makeIPEntry(uint32(ifa.Index), ip)
		ip_entries = append(ip_entries, *ip_entry)
		err = addEntryIpMap(ip_map, ip_entries, 0)
		if err != nil {
			fmt.Printf("Error! populating ip map: %s\n", err)
			return
		}

		//Initialize stats maps for idx
		cntPkt := cntPkt{drop: 0, pass: 0}
		err = ingress_stats_map.Put(uint32(ifa.Index), (cntPkt))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		err = egress_stats_map.Put(uint32(ifa.Index), (cntPkt))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	default:
		fmt.Printf("Mode %v not found\n", mode)
		fmt.Printf("Did you mean?\n ./bin/main --mode add --idx {iface_id} --mac {iface_mac} --ip {iface_ip}\n")
	}

	err = closeMap(m)
	if err != nil {
		fmt.Printf("Error! closing map: %s\n", err)
		return
	}

	return
}
