package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/DelusionalOptimist/dropit/pkg/config"
	"github.com/DelusionalOptimist/dropit/pkg/types"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	FilterMap *bpf.BPFMap
)

func main() {
	viper.AutomaticEnv()

	InterfaceName := pflag.String("interface", "eth0", "Network interface to monitor")
	ConfigPath := pflag.String("config", filepath.Join("opt", "dropit", "dropit.yaml"), "Absolute path to the config file for dropit")

	pflag.Parse()

	if ConfigPath != nil && *ConfigPath != "" {
		fmt.Printf("Filter file path: %s...\n", *ConfigPath)

		err := config.InitConfig(*ConfigPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		fmt.Println("No filters specified...")
	}

	bpfModule, err := bpf.NewModuleFromFile("daemon.o")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	xdpProg, err := bpfModule.GetProgram("intercept_packets")
	if xdpProg == nil {
		fmt.Println(fmt.Errorf("Failed to get xdp program %s", err))
	}

	_, err = xdpProg.AttachXDP(*InterfaceName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	FilterMap, err = bpfModule.GetMap("filter_rules")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else if FilterMap.Name() != "filter_rules" {
		fmt.Println("Wrong map...")
		os.Exit(1)
	} else if FilterMap.Type() != bpf.MapTypeHash {
		fmt.Println("Wrong map type...")
		os.Exit(1)
	}

	updateBPFMap()

	eventsChan := make(chan []byte)
	ringbuf, err := bpfModule.InitRingBuf("events", eventsChan)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer ringbuf.Stop()
	defer ringbuf.Close()

	ringbuf.Poll(300)

	// listen for sigkill,term
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)

	packetIdx := 0
	fmt.Printf(
		"|%-5s|%-19s|%-15s|%-8s|%-15s|%-8s|%-5s|%-10s|%-8s|\n",
		"No.", "Time", "Src IP", "Src Port", "Dest IP", "Dst Port", "Proto", "Size", "Status",
	)

	for {
		select {
		case eventBytes := <-eventsChan:
			packetIdx++
			pk := parseByteData(eventBytes)

			fmt.Printf(
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
			fmt.Printf("Received %s...\nCleaning up...\n", sig.String())
			fmt.Println("Exiting...")
			return
		}
	}
}

// TODO: figure out why byte order is so f'ed up everywhere
func updateBPFMap() {
	for key, value := range config.FilterRuleBytesMap {
		keyBin := binary.BigEndian.Uint32([]byte(key))

		fmt.Printf("Adding map with ID %s: %v\n", key, value)

		keyUnsafe := unsafe.Pointer(&keyBin)
		valueUnsafe := unsafe.Pointer(&value)

		err := FilterMap.Update(keyUnsafe, valueUnsafe)
		if err != nil {
			fmt.Printf("Failed to update bpf map with id: %s err: %s", key, err)
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
