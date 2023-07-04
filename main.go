package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DelusionalOptimist/dropit/pkg/types"
	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
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

	// TODO: config
	interfaceName := os.Getenv("INTERFACE_NAME")
	if interfaceName == "" {
		interfaceName = "eth0"
	}

	_, err = xdpProg.AttachXDP(interfaceName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

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
		"|%-5s|%-19s|%-15s|%-8s|%-15s|%-8s|%-5s|%-10s|\n",
		"No.", "Time", "Src IP", "Src Port", "Dest IP", "Dst Port", "Proto", "Size",
	)

	for {
		select {
		case eventBytes := <- eventsChan:
			packetIdx++
			pk := parseByteData(eventBytes)

			fmt.Printf(
				"|%-5d|%-19s|%-15s|%-8d|%-15s|%-8d|%-5s|%-10d|\n",
				packetIdx,
				time.Now().Format(time.DateTime),
				pk.SourceIP,
				pk.SourcePort,
				pk.DestIP,
				pk.DestPort,
				pk.Protocol,
				pk.Size,
			)

		case sig := <- sigChan:
			fmt.Printf("Received %s...\nCleaning up...\n", sig.String())
			fmt.Println("Exiting...")
			return
		}
	}
}

func parseByteData(data []byte) types.Packet {
	if len(data) == 20 {

		// Since XDP hook picks up data from network directly and we don't convert
		// in C code, the data here is in network byte order (big endian)
		pk := types.Packet{
			Size: binary.BigEndian.Uint32(data[8:12])/1024,
			SourcePort: binary.BigEndian.Uint16(data[12:14]),
			DestPort: binary.BigEndian.Uint16(data[14:16]),
			Protocol: types.GetProtoName(data[16]),

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

		return pk
	}

	return types.Packet{}
}
