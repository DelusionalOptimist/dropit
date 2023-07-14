package types

import (
	"strings"
	"syscall"
)

func GetProtoName(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "TCP"
	case syscall.IPPROTO_UDP:
		return "UDP"
	}
	return ""
}

func GetProtoNumber(proto string) (protoInt uint8) {
	proto = strings.ToLower(proto)
	switch proto {
	case "*":
		protoInt = 0
	case "tcp":
		protoInt = syscall.IPPROTO_TCP
	case "udp":
		protoInt = syscall.IPPROTO_UDP
	default:
		protoInt = syscall.IPPROTO_NONE
	}
	return protoInt
}
