package main

import (
	"fmt"
	"net"
	"unsafe"
	"github.com/cilium/ebpf"
	"flag"
	"os"
	"errors"

)

const MAXLEN = 2000

//Code for monitoring network changes
/*
func ListenNetlink() (*NetlinkListener, error) {
    groups := syscall.RTNLGRP_LINK |
        syscall.RTNLGRP_IPV4_IFADDR |
        syscall.RTNLGRP_IPV6_IFADDR

    s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM,
        syscall.NETLINK_ROUTE)
    if err != nil {
        return nil, fmt.Errorf("socket: %s", err)
    }

    saddr := &syscall.SockaddrNetlink{
        Family: syscall.AF_NETLINK,
        Pid:    uint32(0),
        Groups: uint32(groups),
    }

    err = syscall.Bind(s, saddr)
    if err != nil {
        return nil, fmt.Errorf("bind: %s", err)
    }

    return &NetlinkListener{fd: s, sa: saddr}, nil
}

func (l *NetlinkListener) ReadMsgs() ([]syscall.NetlinkMessage, error) {
    defer func() {
        recover()
    }()

    pkt := make([]byte, 2048)

    n, err := syscall.Read(l.fd, pkt)
    if err != nil {
        return nil, fmt.Errorf("read: %s", err)
    }

    msgs, err := syscall.ParseNetlinkMessage(pkt[:n])
    if err != nil {
        return nil, fmt.Errorf("parse: %s", err)
    }

    return msgs, nil
}

func IsNewAddr(msg *syscall.NetlinkMessage) bool {
    if msg.Header.Type == syscall.RTM_NEWADDR {
        return true
    }

    return false
}

func IsDelAddr(msg *syscall.NetlinkMessage) bool {
    if msg.Header.Type == syscall.RTM_DELADDR {
        return true
    }

    return false
}

func IsRelevant(msg *syscall.IfAddrmsg) bool {
    if msg.Scope == syscall.RT_SCOPE_UNIVERSE ||
        msg.Scope == syscall.RT_SCOPE_SITE {
        return true
    }

    return false
}
*/


//ifindex,mac address mapping for the interfaces
type entry struct {
	ifIdx uint32
	mac   net.HardwareAddr
}

//cntPkt resembles cntPkt in ebpf kernel code
type cntPkt struct{
  drop uint32
  pass uint32
}

type statEntry struct {
     ifIdx uint32
     count cntPkt 
}

func initializeStatsMap(m *ebpf.Map, entries []uint32) (error) {
	fmt.Printf("initStatsMap : Info: %v keysize: %v valueSize: %v",m.String(),m.KeySize(), m.ValueSize())
	for _, entry := range entries {
     	        cntPkt := cntPkt{drop:0,pass:0} 
		err := m.Put(entry, (cntPkt));
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

func makeEntry(ifIdx uint32, mac net.HardwareAddr) *entry {
	var en entry
	en.ifIdx = ifIdx
	en.mac = mac
	return &en
}

func getAllMACs() ([]entry, error) {
    ifas, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    entries := []entry{}
    for _, ifa := range ifas {
        a := ifa.HardwareAddr.String()
        if a != "" {
		fmt.Printf("ifIndex: %v macAddr: %v size_mac: %d\n",
		ifa.Index,ifa.HardwareAddr, int(unsafe.Sizeof(ifa.HardwareAddr)))
		e := makeEntry(uint32(ifa.Index),ifa.HardwareAddr)
		entries=append(entries,*e)
        }
    }
    return entries, nil
}

func getInterface(idx int) (*net.Interface,error){
	ifa,err := net.InterfaceByIndex(idx)
	if err != nil{
		fmt.Printf("Error: %v",err.Error())
		return nil,err
	}
	return ifa,nil

}

//Returns indices of interfaces
func getAllIfaceIndices() ([]uint32,error){
    ifas, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
	entries := []uint32{}
    for _, ifa := range ifas {
        a := ifa.HardwareAddr.String()
        if a != "" {
		fmt.Printf("ifIndex: %v macAddr: %v size_mac: %d\n",
		ifa.Index,ifa.HardwareAddr, int(unsafe.Sizeof(ifa.HardwareAddr)))
		entries=append(entries,uint32(ifa.Index))
        }
    }
    return entries, nil

}

//This will overwrite previous entry if any
func addEntryMap(m *ebpf.Map, entries []entry, rand int)(error){
	for _, ifa := range entries {
		err := m.Put(ifa.ifIdx+ uint32(rand), []byte(ifa.mac));
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

//This will ignore missing entries and always return success
func delEntryMap(m *ebpf.Map,keys []interface{}) (error){
	for _, ifa := range keys {
		var err error
		switch ifa.(type) {
		case uint32:
			err = m.Delete(ifa.(uint32))
		case string:
			err = m.Delete(ifa.(string))
		}
		fmt.Printf("[delMap] ifIdx: %v\n",ifa)
		if err!= nil {
			fmt.Printf("[delMap] Warn: %v\n", err)
		}
	}
	return nil
}

func createArray( maxEntries int, keySize int, valueSize int) (*ebpf.Map,error) {
	fmt.Printf("KeySize: %d ValueSize: %d MaxEntries: %d\n", keySize, valueSize, maxEntries)
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(keySize),
		ValueSize:  uint32(valueSize),
		MaxEntries: uint32(maxEntries),
	})
	if err != nil {
		return nil,err
	}
	return m,nil
}

func pinMap(m *ebpf.Map, path string) error {
	if err := m.Pin(path); err != nil {
		m.Close()
		fmt.Printf("[pinMap] Error! pin map: %s\n", err)
		return err
	}
	return nil
}


func closeMap(m *ebpf.Map) error {
	return m.Close()
}

func getMap(path string)(*ebpf.Map,error){
	return ebpf.LoadPinnedMap(path) 
}

func pinOrGetMap(path string, m *ebpf.Map)(*ebpf.Map,error){
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err = pinMap(m, path)
		if err != nil {
			fmt.Printf("Error! PinOrGetMap map: %s\n", err)
			return m,err
		}
		return m,nil
	} else{
		temp, err := getMap(path)
		if err != nil {
			fmt.Printf("Error! PinOrGetMap map: %s\n", err)
			return m,err
		}
		return temp,nil
	}
}


//We are not unpinning the map XXX
//We should Freeze() userspace to avoid maniplulation XXX
// Userspace should keep updating interfaces when they come and go down? So dont freeze()?? XXX
func main() {

	var mode string
	var idx  int

	flag.StringVar(&mode, "mode","init","Mode can be init or add")
	flag.IntVar(&idx,"idx",0,"iface index")
	flag.Parse()
	fmt.Printf("Mode: %v idx: %v",mode,idx)

	
     	//ifaceMacMapPath := os.args[1]
     	ifaceMacMapPath := "/sys/fs/bpf/tc/globals/iface_map"
	//egressCountMapPath := os.args[2]
	egressCountMapPath := "/sys/fs/bpf/tc/globals/egress_iface_stat_map"
	//ingressCountMapPath := os.args[3]
	ingressCountMapPath := "/sys/fs/bpf/tc/globals/ingress_iface_stat_map"
	
	//path := "/sys/fs/bpf/tc/globals/iface_map"
	
	var mac_map *ebpf.Map
	var m *ebpf.Map
	var ingress_stats_map *ebpf.Map
	var egress_stats_map *ebpf.Map
	
	var en entry
	var ct cntPkt

	mac_map, err := createArray(MAXLEN,
		//len(macArr),
		int(unsafe.Sizeof(en.ifIdx)),
		//int(unsafe.Sizeof(en.mac)))
		6)
	mac_map,err = pinOrGetMap(ifaceMacMapPath,mac_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}
	
	egress_stats_map,err = createArray(MAXLEN,int(unsafe.Sizeof(en.ifIdx)),int(unsafe.Sizeof(ct)))
	egress_stats_map,err = pinOrGetMap(egressCountMapPath,egress_stats_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	ingress_stats_map,err = createArray(MAXLEN,int(unsafe.Sizeof(en.ifIdx)),int(unsafe.Sizeof(ct)))
	ingress_stats_map,err = pinOrGetMap(ingressCountMapPath,ingress_stats_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	if( mode == "init"){
		macArr,err := getAllMACs()
		if err != nil || len(macArr) == 0 {
			return
		}
		err = addEntryMap(mac_map, macArr, 0)
		if err != nil {
			fmt.Printf("Error! populating map: %s\n", err)
			return
		}
		ifaceIndices,err := getAllIfaceIndices();
		initializeStatsMap(egress_stats_map,ifaceIndices)
		initializeStatsMap(ingress_stats_map,ifaceIndices)
		
	} else{
		ifa,err := getInterface(idx)
		if err != nil {
			fmt.Printf("Could not get interface %v\n",err.Error())
			//exit(0)
		}
		entries := []entry{}
		e := makeEntry(uint32(ifa.Index),ifa.HardwareAddr)
		entries=append(entries,*e)
		err = addEntryMap(mac_map, entries, 0)
		if err != nil {
			fmt.Printf("Error! populating map: %s\n", err)
			return
		}
		//Initialize stats maps for idx
		cntPkt := cntPkt{drop:0,pass:0}
		err = ingress_stats_map.Put(uint32(ifa.Index),(cntPkt))
		if err != nil {
                        fmt.Printf("Error: %v\n", err)
                        return
                }
		err = egress_stats_map.Put(uint32(ifa.Index), (cntPkt));
		if err != nil {
                        fmt.Printf("Error: %v\n", err)
                        return
                }

	}	

	

	

	
	/*arr := []interface{}{uint32(2),uint32(3),uint32(4)}
	err = delEntryMap(m, arr)
	if err != nil {
		fmt.Printf("Error! deleting map entries: %s\n", err)
		return
	}*/

	err = closeMap(m)
	if err != nil {
		fmt.Printf("Error! closing map: %s\n", err)
		return
	}

	return
}
