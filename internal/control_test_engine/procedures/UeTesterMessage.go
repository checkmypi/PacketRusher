package procedures

import "my5G-RANTester/internal/control_test_engine/ue/context"

type UeTesterMessageType int32

const (
	Registration      UeTesterMessageType = 0
	Deregistration    UeTesterMessageType = 1
	NewPDUSession     UeTesterMessageType = 2
	DestroyPDUSession UeTesterMessageType = 3
	Terminate         UeTesterMessageType = 4
	Kill              UeTesterMessageType = 5
)

type UeTesterMessage struct {
	Type UeTesterMessageType
	Param *context.PDUSession
}