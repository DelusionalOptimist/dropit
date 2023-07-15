package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/DelusionalOptimist/dropit/pkg/config"
	"github.com/DelusionalOptimist/dropit/pkg/types"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	// userspace filter map
	FilterRuleBytesMap = make(map[string]types.FilterRuleBytes, 1)

	// reference to kernel space BPF map for filters
	FilterMap *bpf.BPFMap
)

func main() {
	InterfaceName := pflag.String("interface", "eth0", "Network interface to monitor")
	ConfigPath := pflag.String("config", filepath.Join("opt", "dropit", "dropit.yaml"), "Absolute path to the config file for dropit")

	pflag.Parse()

	if ConfigPath != nil && *ConfigPath != "" {
		log.Printf("Filter file path: %s...\n", *ConfigPath)

		viper.SetConfigFile(*ConfigPath)

		var err error
		FilterRuleBytesMap, err = config.GetConfig()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		viper.OnConfigChange(func(in fsnotify.Event) {
			if in.Op == fsnotify.Write {

				frMapNew, err := config.GetConfig()
				if err != nil {
					log.Printf("Error while getting new config: %s\n", err)
					log.Println("Filter rules won't be updated.")
					return
				}

				if reflect.DeepEqual(FilterRuleBytesMap, frMapNew) {
					// no actual changes, just an event
					log.Println("Filter rules updated. No changes to do...")
					return
				}

				log.Printf("Filter file updated. Getting new filter rules...\n")

				for newRule, newVal := range frMapNew {
					if _, ok := FilterRuleBytesMap[newRule]; ok {
						// if rule already exists, compare it
						UpdateBPFMap("MODIFY", newRule, newVal)
					} else {
						// new rule added, add it
						UpdateBPFMap("ADD", newRule, newVal)
					}
				}

				// check if any rule was deleted
				for curRule := range FilterRuleBytesMap {
					if _, ok := frMapNew[curRule]; !ok {
						UpdateBPFMap("DELETE", curRule, types.FilterRuleBytes{})
					}
				}

			}
		})

		viper.WatchConfig()

	} else {
		log.Println("No filters specified...")
	}

	bpfModule, err := bpf.NewModuleFromFile("daemon.o")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	xdpProg, err := bpfModule.GetProgram("intercept_packets")
	if xdpProg == nil {
		log.Println(fmt.Errorf("Failed to get xdp program %s", err))
	}

	_, err = xdpProg.AttachXDP(*InterfaceName)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	FilterMap, err = bpfModule.GetMap("filter_rules")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	} else if FilterMap.Name() != "filter_rules" {
		log.Println("Wrong map...")
		os.Exit(1)
	} else if FilterMap.Type() != bpf.MapTypeHash {
		log.Println("Wrong map type...")
		os.Exit(1)
	}

	initBPFMap()

	eventsChan := make(chan []byte)
	ringbuf, err := bpfModule.InitRingBuf("events", eventsChan)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	defer ringbuf.Stop()
	defer ringbuf.Close()

	ringbuf.Poll(300)

	// listen for sigkill,term
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)

	packetIdx := 0
	log.Printf(
		"|%-5s|%-19s|%-15s|%-8s|%-15s|%-8s|%-5s|%-10s|%-8s|\n",
		"No.", "Time", "Src IP", "Src Port", "Dest IP", "Dst Port", "Proto", "Size", "Status",
	)

	for {
		select {
		case eventBytes := <-eventsChan:
			packetIdx++
			pk := parseByteData(eventBytes)

			log.Printf(
				"|%-5d|%-19s|%-15s|%-8d|%-15s|%-8d|%-5s|%-10d|%-8s|\n",
				packetIdx,
				time.Now().Format(time.DateTime),
				pk.SourceIP,
				pk.SourcePort,
				pk.DestIP,
				pk.DestPort,
				pk.Protocol,
				pk.Size,
				pk.Status,
			)

		case sig := <-sigChan:
			log.Printf("Received %s...\nCleaning up...\n", sig.String())
			log.Println("Exiting...")
			return
		}
	}
}

// TODO: figure out why byte order is so f'ed up everywhere
func UpdateBPFMap(action string, ruleName string, ruleVal types.FilterRuleBytes) error {
	keyBin := binary.BigEndian.Uint32([]byte(ruleName))
	keyUnsafe := unsafe.Pointer(&keyBin)

	switch action{
	case "ADD":
		// add a new map
		log.Printf("Adding map with ID %s: %v\n", ruleName, ruleVal)

		valueUnsafe := unsafe.Pointer(&ruleVal)

		err := FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to update bpf map with id: %s err: %s", ruleName, err)
		}

		FilterRuleBytesMap[ruleName] = ruleVal

	case "MODIFY":
		// no changes
		if reflect.DeepEqual(FilterRuleBytesMap[ruleName], ruleVal) {
			return nil
		}

		// update
		log.Printf("Updating map with ID %s: %v\n", ruleName, ruleVal)

		valueUnsafe := unsafe.Pointer(&ruleVal)

		err := FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to update bpf map with id: %s err: %s", ruleName, err)
		}

		FilterRuleBytesMap[ruleName] = ruleVal

	case "DELETE":
		// delete
		log.Printf("Deleting map with ID %s\n", ruleName)

		err := FilterMap.DeleteKey(keyUnsafe)
		if err != nil {
			return fmt.Errorf("Failed to delete bpf map with id: %s err: %s", ruleName, err)
		}

		delete(FilterRuleBytesMap, ruleName)
	}

	return nil
}

func initBPFMap() {
	for key, value := range FilterRuleBytesMap {
		keyBin := binary.BigEndian.Uint32([]byte(key))

		log.Printf("Adding map with ID %s: %v\n", key, value)

		keyUnsafe := unsafe.Pointer(&keyBin)
		valueUnsafe := unsafe.Pointer(&value)

		err := FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			log.Printf("Failed to update bpf map with id: %s err: %s", key, err)
		}
	}
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
