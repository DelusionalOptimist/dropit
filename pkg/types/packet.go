package types

type Packet struct {
	SourceIP   string
	DestIP     string
	Size       uint32
	SourcePort uint16
	DestPort   uint16
	Protocol   string
	Status     string
}
