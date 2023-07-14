package config

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/DelusionalOptimist/dropit/pkg/types"
	"github.com/spf13/viper"
)

var (
	Cfg                Config
	FilterRuleBytesMap = make(map[string]FilterRuleBytes, 1)
)

type Config struct {
	Rules []struct {
		ID              string `yaml:"id"`
		SourceIP        string `yaml:"sourceIP"`
		SourcePort      string `yaml:"sourcePort"`
		DestinationPort string `yaml:"destinationPort"`
		Protocol        string `yaml:"protocol"`
	} `yaml:"rules"`
}

type FilterRuleBytes struct {
	SourceIP        uint32
	SourcePort      uint16
	DestinationPort uint16
	Protocol        uint8
}

func InitConfig(configPath string) error {
	if err := readConfig(configPath); err != nil {
		return err
	}

	if err := validateConfig(); err != nil {
		return err
	}

	if err := parseConfig(); err != nil {
		return err
	}

	return nil
}

func readConfig(configPath string) (errorStr error) {
	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err == nil {
		return nil
	}

	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		errorStr = fmt.Errorf("Filter file not found: %s", err)
	} else if _, ok := err.(viper.ConfigParseError); ok {
		errorStr = fmt.Errorf("Failed to parse config: %s", err)
	} else {
		errorStr = fmt.Errorf("Unknown err: %s", err)
	}

	return errorStr
}

func validateConfig() error {
	viper.SetConfigType("yaml")
	err := viper.Unmarshal(&Cfg)
	if err != nil {
		return err
	}

	return nil
}

func parseConfig() error {
	for _, rule := range Cfg.Rules {
		ip, err := netip.ParseAddr(rule.SourceIP)
		if err != nil {
			return fmt.Errorf("Rule ID: %s. Failed to read sourceIP. %s", rule.ID, err)
		}
		srcIP := binary.LittleEndian.Uint32(ip.AsSlice())

		var destPort uint64
		if rule.DestinationPort == "*" {
			destPort = 0
		} else {
			destPort, err = strconv.ParseUint(rule.DestinationPort, 10, 16)
			if err != nil {
				return fmt.Errorf("Rule ID: %s. Failed to read destPort. %s", rule.ID, err)
			}
		}

		//var srcPort uint64
		//if rule.SourcePort == "*" {
		//	srcPort = 0
		//} else {
		//	srcPort, err := strconv.ParseUint(rule.SourcePort, 10, 16)
		//	if err != nil {
		//		fmt.Println("Failed to read sourcePort from rule ID:", rule.ID, err)
		//	}
		//}

		protocol := types.GetProtoNumber(rule.Protocol)
		if protocol == syscall.IPPROTO_NONE {
			return fmt.Errorf("Rule: %s. Bad protocol specified: %s. Possible values: TCP, UDP or *", rule.ID, rule.Protocol)
		}

		byteRule := FilterRuleBytes{
			SourceIP: srcIP,
			//SourcePort: uint16(srcPort << 8),
			DestinationPort: uint16(destPort << 8),
			Protocol:        protocol,
		}

		FilterRuleBytesMap[rule.ID] = byteRule
	}

	return nil
}
