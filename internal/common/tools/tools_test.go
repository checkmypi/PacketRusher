/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Valentin D'Emmanuele
 */
package tools

import (
	"testing"

	"my5G-RANTester/config"
	gnbContext "my5G-RANTester/internal/control_test_engine/gnb/context"
	"my5G-RANTester/internal/control_test_engine/procedures"
)

func TestUEGnbSelectionAndHandoverSequence(t *testing.T) {
	cases := []struct {
		name   string
		ueID   int
		gnbIDs []string
		want   []string
	}{
		{"single gNB", 1, []string{"000008"}, []string{"000008", "000008", "000008"}},
		{"first dedicated UE", 1, []string{"000008", "000009", "00000A", "00000B"}, []string{"000008", "000009", "00000A", "00000B", "000008"}},
		{"second dedicated UE", 2, []string{"000008", "000009", "00000A", "00000B"}, []string{"000009", "00000A", "00000B", "000008", "000009"}},
		{"last dedicated UE", 4, []string{"000008", "000009", "00000A", "00000B"}, []string{"00000B", "000008", "000009", "00000A", "00000B"}},
		{"more UEs than gNBs", 7, []string{"000008", "000009", "00000A"}, []string{"000008", "000009", "00000A", "000008"}},
		{"handover with two gNBs", 1, []string{"000008", "000009"}, []string{"000008", "000009", "000008", "000009"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := UESimulationConfig{UeId: tc.ueID, Gnbs: make(map[string]*gnbContext.GNBContext)}
			sim.Cfg = config.Config{GNodeB: config.GNodeB{PlmnList: config.PlmnList{GnbId: "000008"}}}
			for _, id := range tc.gnbIDs {
				sim.Gnbs[id] = nil
			}
			for offset, want := range tc.want {
				got := sim.gnbID(offset)
				if got != want {
					t.Errorf("offset %d: gNB %s, want %s", offset, got, want)
				}
				if _, exists := sim.Gnbs[got]; !exists {
					t.Errorf("selected nonexistent gNB %s", got)
				}
			}
		})
	}
}

func TestPduSessionFor(t *testing.T) {
	sessions := []procedures.PduSessionStatus{{Id: 1, State: "active"}, {Id: 2, State: "pending"}, {Id: 3, State: "rejected"}}
	for _, test := range []struct {
		action    string
		requested int
		id        int
		valid     bool
	}{
		{"pdu-establish", 0, 4, true},
		{"pdu-establish", 9, 9, true},
		{"pdu-establish", 2, 0, false},
		{"pdu-release", 0, 1, true},
		{"pdu-release", 3, 3, true},
		{"pdu-release", 2, 0, false},
		{"pdu-release", 9, 0, false},
	} {
		id, err := pduSessionFor(test.action, test.requested, sessions)
		if (err == nil) != test.valid || id != test.id {
			t.Errorf("pduSessionFor(%s, %d) = %d, %v, want %d, valid: %t", test.action, test.requested, id, err, test.id, test.valid)
		}
	}
	full := []procedures.PduSessionStatus{}
	for id := 1; id <= 15; id++ {
		full = append(full, procedures.PduSessionStatus{Id: id, State: "pending"})
	}
	if _, err := pduSessionFor("pdu-establish", 0, full); err == nil {
		t.Error("pduSessionFor(pdu-establish) found a free ID among 15 sessions")
	}
	if _, err := pduSessionFor("pdu-release", 0, full); err == nil {
		t.Error("pduSessionFor(pdu-release) released a pending session")
	}
}
