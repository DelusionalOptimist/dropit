package config

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"github.com/DelusionalOptimist/dropit/pkg/types"
	"github.com/spf13/viper"
)

func DirectionStringToInt(direction string) uint8 {
	switch strings.ToLower(direction) {
	case "ingress":
		return 0
	case "egress":
		return 1
	default:
		return 2
	}
}

func DirectionIntToString(direction uint8) string {
	switch direction {
	case 0:
		return "ingress"
	case 1:
		return "egress"
	default:
		return "unknown"
	}
}

type Config struct {
	Rules []struct {
		ID              string `yaml:"id"`
		SourceIP        string `yaml:"sourceIP"`
		SourcePort      string `yaml:"sourcePort"`
		DestinationPort string `yaml:"destinationPort"`
		Protocol        string `yaml:"protocol"`
		Direction       string `yaml:"direction"`
	} `yaml:"rules"`
}

func GetConfig() (map[string]types.FilterRuleBytes, error) {
	cfg := &Config{}
	if err := readConfig(); err != nil {
		return nil, err
	}

	if err := cfg.validateConfig(); err != nil {
		return nil, err
	}

	fr, err := cfg.parseConfig()
	if err != nil {
		return nil, err
	}

	return fr, nil
}

func readConfig() (errorStr error) {
	err := viper.ReadInConfig()
	if err == nil {
		return nil
	}

	// viper issue: ConfigFileNotFoundError doesn't work for non existent directories?
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		errorStr = fmt.Errorf("Filter file not found: %s", err)
	} else if _, ok := err.(viper.ConfigParseError); ok {
		errorStr = fmt.Errorf("Failed to parse config: %s", err)
	} else {
		errorStr = fmt.Errorf("Unknown error: %s", err)
	}

	return errorStr
}

func (cfg *Config) validateConfig() error {
	viper.SetConfigType("yaml")
	err := viper.Unmarshal(cfg)
	if err != nil {
		return err
	}

	return nil
}

func (cfg *Config) parseConfig() (map[string]types.FilterRuleBytes, error) {
	fr := make(map[string]types.FilterRuleBytes)
	for _, rule := range cfg.Rules {
		var err error
		var srcIP uint32
		if rule.SourceIP == "*" {
			srcIP = 0
		} else {
			ip, err := netip.ParseAddr(rule.SourceIP)
			if err != nil {
				return fr, fmt.Errorf("Rule ID: %s. Failed to read sourceIP. %s", rule.ID, err)
			}
			srcIP = binary.LittleEndian.Uint32(ip.AsSlice())
		}

		var destPort uint64
		if rule.DestinationPort == "*" {
			destPort = 0
		} else {
			destPort, err = strconv.ParseUint(rule.DestinationPort, 10, 16)
			if err != nil {
				return fr, fmt.Errorf("Rule ID: %s. Failed to read destPort. %s", rule.ID, err)
			}
		}

		var srcPort uint64
		if rule.SourcePort == "*" {
			srcPort = 0
		} else {
			srcPort, err = strconv.ParseUint(rule.SourcePort, 10, 16)
			if err != nil {
				return fr, fmt.Errorf("Rule ID: %s. Failed to read sourcePort. %s", rule.ID, err)
			}
		}

		protocol := types.GetProtoNumber(rule.Protocol)
		if protocol == syscall.IPPROTO_NONE {
			return fr, fmt.Errorf("Rule: %s. Bad protocol specified: %s. Possible values: TCP, UDP or *", rule.ID, rule.Protocol)
		}

		byteRule := types.FilterRuleBytes{
			SourceIP:        srcIP,
			SourcePort:      uint16(srcPort<<8 | srcPort>>8),
			DestinationPort: uint16(destPort<<8 | destPort>>8),
			Protocol:        protocol,
			Direction:       DirectionStringToInt(rule.Direction),
		}

		fr[rule.ID] = byteRule
	}

	return fr, nil
}
