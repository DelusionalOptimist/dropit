package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/DelusionalOptimist/dropit/pkg/monitor"
	"github.com/spf13/pflag"
)

func main() {
	InterfaceName := pflag.String("interface", "eth0", "Network interface to monitor")
	ConfigPath := pflag.String("config", filepath.Join(string(os.PathSeparator), "opt", "dropit", "dropit.yaml"), "Absolute path to optional config file containing filter rules")

	pflag.Parse()

	mon := monitor.NewMonitor()

	err := mon.StartMonitor(InterfaceName, ConfigPath)
	if err != nil {
		log.Fatalln("failed to initialize monitor:", err)
	}
}
