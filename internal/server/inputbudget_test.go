package server

import "testing"

func TestInputBudgetReleasesAndEnforcesBothCaps(t *testing.T) {
	a := NewInputBudget(8)
	if !a.Reserve(8) || a.Reserve(1) {
		t.Fatal("request budget did not enforce its cap")
	}
	b := NewInputBudget(8)
	if !b.Reserve(1) {
		t.Fatal("independent request budget was unexpectedly blocked")
	}
	a.Release()
	b.Release()

	full := NewInputBudget(int(maxProcessInputBytes))
	if !full.Reserve(int(maxProcessInputBytes)) {
		t.Fatal("process budget would not reserve its ceiling")
	}
	other := NewInputBudget(1)
	if other.Reserve(1) {
		t.Fatal("process-wide input budget allowed an overcommit")
	}
	full.Release()
	if !other.Reserve(1) {
		t.Fatal("released process-wide input budget was not reusable")
	}
	other.Release()
}
