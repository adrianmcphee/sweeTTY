package server

import "sync/atomic"

// maxProcessInputBytes is the amount of attacker-controlled protocol input that
// active handlers may retain at once. Per-request budgets below this ceiling keep
// one connection honest; this process-wide pool stops a botnet of otherwise-valid
// requests from multiplying those allocations until the heap is exhausted.
const maxProcessInputBytes int64 = 64 << 20

var processInputBytes atomic.Int64

// InputBudget accounts for strings and bodies retained while one protocol request
// is being parsed. A budget must be released when the request handler returns.
type InputBudget struct {
	limit    int64
	reserved int64
}

// NewInputBudget starts a request budget with a protocol-specific ceiling.
func NewInputBudget(limit int) *InputBudget {
	if limit <= 0 {
		limit = 1
	}
	return &InputBudget{limit: int64(limit)}
}

// Reserve claims n bytes from both the request and process-wide budgets.
func (b *InputBudget) Reserve(n int) bool {
	if n <= 0 {
		return true
	}
	want := int64(n)
	if want > b.limit-b.reserved {
		return false
	}
	for {
		cur := processInputBytes.Load()
		if want > maxProcessInputBytes-cur {
			return false
		}
		if processInputBytes.CompareAndSwap(cur, cur+want) {
			b.reserved += want
			return true
		}
	}
}

// Release returns all claims made by the request to the process-wide pool.
func (b *InputBudget) Release() {
	if b.reserved == 0 {
		return
	}
	processInputBytes.Add(-b.reserved)
	b.reserved = 0
}
