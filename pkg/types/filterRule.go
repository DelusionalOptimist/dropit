package types

type FilterRuleBytes struct {
	SourceIP            uint32
	SourcePort          uint16
	DestinationPort     uint16
	Protocol            uint8
	Direction           uint8
	RateLimitTimeWindow uint64
	RateLimitMaxCount   uint64
}
