package monitor

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/DelusionalOptimist/dropit/pkg/config"
	"github.com/DelusionalOptimist/dropit/pkg/types"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Monitor struct {
	// userspace filter map
	FilterRuleBytesMap map[string]types.FilterRuleBytes

	// reference to kernel space BPF map for filters
	FilterMap *bpf.BPFMap

	// Mapping rule ID's string keys to BPF Map's uint32 keys
	// I don't want to use string as BPF map key, thus this workaround
	RuleBPFKeyMap map[string]uint32

	SigChan chan(os.Signal)
}

func NewMonitor() *Monitor {
	mon := &Monitor{
		FilterRuleBytesMap: make(map[string]types.FilterRuleBytes),
		RuleBPFKeyMap: make(map[string]uint32),
		SigChan: make(chan os.Signal, 1),
	}

	return mon
}

func (m *Monitor) StartMonitor(interfaceName, cfgPath *string) error {
	if cfgPath != nil && *cfgPath != "" {
		err := m.loadConfig(*cfgPath)
		if err != nil {
			return err
		}
	}

	bpfModule, err := bpf.NewModuleFromFile("daemon.o")
	if err != nil {
		return err
	}
	defer bpfModule.Close()

	if interfaceName != nil && *interfaceName != "" {
		err = m.InitBPF(*interfaceName, bpfModule)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Interface name can't be empty")
	}

	m.loadBPFMap()

	eventsChan := make(chan []byte)
	ringbuf, err := bpfModule.InitRingBuf("events", eventsChan)
	if err != nil {
		return err
	}

	defer ringbuf.Stop()
	defer ringbuf.Close()

	ringbuf.Poll(300)

	// listen for sigkill,term
	signal.Notify(m.SigChan, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)

	m.StartLogging(eventsChan, ringbuf)

	return nil
}

func (m *Monitor) loadConfig(cfgPath string) error {
	_, err := os.Stat(cfgPath)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			log.Println("Error while reading filter file. Running in monitor only mode.")
			return nil
		}
	}

	log.Printf("Filter file path: %s...\n", cfgPath)

	viper.SetConfigFile(cfgPath)

	m.FilterRuleBytesMap, err = config.GetConfig()
	if err != nil {
		return err
	}

	viper.OnConfigChange(m.configChangeHandler)
	viper.WatchConfig()

	return nil
}


func (m *Monitor) InitBPF(interfaceName string, bpfModule *bpf.Module) error {

	err := bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	xdpProg, err := bpfModule.GetProgram("intercept_packets")
	if xdpProg == nil {
		if err != nil {
			return fmt.Errorf("Failed to get xdp program %s", err)
		}
		return fmt.Errorf("Empty xdp program loaded")
	}

	_, err = xdpProg.AttachXDP(interfaceName)
	if err != nil {
		return err
	}

	m.FilterMap, err = bpfModule.GetMap("filter_rules")
	if err != nil {
		return err
	} else if m.FilterMap.Name() != "filter_rules" {
		return fmt.Errorf("Wrong map")
	} else if m.FilterMap.Type() != bpf.MapTypeHash {
		return fmt.Errorf("Wrong map type")
	}

	return nil
}

func (m *Monitor) StartLogging(eventsChan chan([]byte), ringbuf *bpf.RingBuffer) error {

	packetIdx := 0
	log.Printf(
		"|%-5s|%-15s|%-8s|%-15s|%-8s|%-5s|%-10s|%-8s|\n",
		"No.", "Src IP", "Src Port", "Dest IP", "Dst Port", "Proto", "Size", "Status",
	)

	for {
		select {
		case eventBytes := <-eventsChan:
			packetIdx++
			pk := parseByteData(eventBytes)

			log.Printf(
				"|%-5d|%-15s|%-8d|%-15s|%-8d|%-5s|%-10d|%-8s|\n",
				packetIdx,
				pk.SourceIP,
				pk.SourcePort,
				pk.DestIP,
				pk.DestPort,
				pk.Protocol,
				pk.Size,
				pk.Status,
			)

		case sig := <-m.SigChan:
			log.Printf("Received %s...\nCleaning up...\n", sig.String())
			log.Println("Exiting...")
			return nil
		}
	}
}

func (m *Monitor) configChangeHandler(in fsnotify.Event) {
	if in.Op == fsnotify.Write {

		frMapNew, err := config.GetConfig()
		if err != nil {
			log.Printf("Error while getting new config: %s\n", err)
			log.Println("Filter rules won't be updated.")
			return
		}

		if reflect.DeepEqual(m.FilterRuleBytesMap, frMapNew) {
			// no actual changes, just an event
			log.Println("Filter file updated. No changes to do...")
			return
		}

		log.Printf("Filter file updated. Getting new filter rules...\n")

		for newRule, newVal := range frMapNew {
			if _, ok := m.FilterRuleBytesMap[newRule]; ok {
				// if rule already exists, compare it with current rule
				m.updateBPFMap("MODIFY", newRule, newVal)
			} else {
				// new rule added, add it to the map
				m.updateBPFMap("ADD", newRule, newVal)
			}
		}

		// check if any rule was deleted
		for curRule := range m.FilterRuleBytesMap {
			if _, ok := frMapNew[curRule]; !ok {
				m.updateBPFMap("DELETE", curRule, types.FilterRuleBytes{})
			}
		}
	}
}

func (m *Monitor) loadBPFMap() {
	for key, value := range m.FilterRuleBytesMap {
		intKey := uint32(len(m.RuleBPFKeyMap) + 1)

		log.Printf("Adding map with ID %s: %v\n", key, value)

		keyUnsafe := unsafe.Pointer(&intKey)
		valueUnsafe := unsafe.Pointer(&value)

		err := m.FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			log.Printf("Failed to update bpf map with id: %s err: %s", key, err)
		}

		m.RuleBPFKeyMap[key] = intKey
	}
}

// TODO: figure out why byte order is so f'ed up everywhere
func (m *Monitor) updateBPFMap(action string, ruleName string, ruleVal types.FilterRuleBytes) error {
	var intKey uint32
	var ok bool

	// use value if int key exists, else we create one
	if intKey, ok = m.RuleBPFKeyMap[ruleName]; !ok {
		intKey = uint32(len(m.RuleBPFKeyMap) + 1)
	}

	keyUnsafe := unsafe.Pointer(&intKey)

	switch action {
	case "ADD":
		// add a new map
		log.Printf("Adding map with ID %s: %v\n", ruleName, ruleVal)

		valueUnsafe := unsafe.Pointer(&ruleVal)

		err := m.FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to update bpf map with id: %s err: %s", ruleName, err)
		}

		m.FilterRuleBytesMap[ruleName] = ruleVal
		m.RuleBPFKeyMap[ruleName] = intKey

	case "MODIFY":
		// no changes
		if reflect.DeepEqual(m.FilterRuleBytesMap[ruleName], ruleVal) {
			return nil
		}

		// update
		log.Printf("Updating map with ID %s: %v\n", ruleName, ruleVal)

		valueUnsafe := unsafe.Pointer(&ruleVal)

		err := m.FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to update bpf map with id: %s err: %s", ruleName, err)
		}

		m.FilterRuleBytesMap[ruleName] = ruleVal

	case "DELETE":
		// delete
		log.Printf("Deleting map with ID %s\n", ruleName)

		err := m.FilterMap.DeleteKey(keyUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to delete bpf map with id: %s err: %s", ruleName, err)
		}

		delete(m.FilterRuleBytesMap, ruleName)
		delete(m.RuleBPFKeyMap, ruleName)
	}

	return nil
}

func parseByteData(data []byte) types.Packet {
	if len(data) == 20 {

		// Since XDP hook picks up data from network directly and we don't convert
		// in C code, the data here is in network byte order (big endian)
		pk := types.Packet{
			Size:       binary.BigEndian.Uint32(data[8:12]) / 1024,
			SourcePort: binary.BigEndian.Uint16(data[12:14]),
			DestPort:   binary.BigEndian.Uint16(data[14:16]),
			Protocol:   types.GetProtoName(data[16]),
			Status:     "Passed",

			// Using gopacket
			//Protocol: layers.IPProtocol(data[16]).String(),
		}

		srcIP, ok := netip.AddrFromSlice(data[0:4])
		if ok {
			pk.SourceIP = srcIP.String()
		}

		dstIP, ok := netip.AddrFromSlice(data[4:8])
		if ok {
			pk.DestIP = dstIP.String()
		}

		isDropped := data[17]
		if isDropped == 1 {
			pk.Status = "Dropped"
		}

		return pk
	}

	return types.Packet{}
}
