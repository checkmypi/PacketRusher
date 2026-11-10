/**
 * SPDX-License-Identifier: Apache-2.0
 */
package config

import "testing"

func TestDnnOfUe(t *testing.T) {
	ue := Ue{Dnn: "internet"}
	if got := ue.DnnOfUe(3); got != "internet" {
		t.Fatalf("without uednns: got %q, want internet", got)
	}
	ue.UeDnns = []string{"internet", "ims", "dnn3", "dnn4"}
	for id, want := range map[int]string{1: "internet", 2: "ims", 3: "dnn3", 4: "dnn4", 5: "internet", 0: "internet"} {
		if got := ue.DnnOfUe(id); got != want {
			t.Errorf("UE %d: got %q, want %q", id, got, want)
		}
	}
}
