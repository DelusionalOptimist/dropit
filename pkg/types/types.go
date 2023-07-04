package types

type Packet struct {
	SourceIP string
  SourcePort uint16
	DestIP string
  DestPort uint16
	Protocol string
	Size uint32
}
