package main

import (
	"math"
	"strings"
	"testing"
)

func TestUint32OptInRange(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want uint32
	}{
		{"mux", 0, 0},
		{"mux", 1, 1},
		{"fwmark", math.MaxUint32, math.MaxUint32},
	}
	for _, c := range cases {
		got, err := uint32Opt(c.name, c.in)
		if err != nil {
			t.Errorf("uint32Opt(%q, %d) returned error: %v", c.name, c.in, err)
		}
		if got != c.want {
			t.Errorf("uint32Opt(%q, %d) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

func TestUint32OptOutOfRange(t *testing.T) {
	// tooBig is evaluated in int context; this relies on int being 64-bit (true
	// for all six CI targets). A hypothetical 32-bit port would make this
	// constant overflow int at compile time — an intentional tripwire, not a
	// silent bug.
	const tooBig = math.MaxUint32 + 1
	cases := []struct {
		name string
		in   int
	}{
		{"mux", -1},
		{"fwmark", tooBig},
	}
	for _, c := range cases {
		_, err := uint32Opt(c.name, c.in)
		if err == nil {
			t.Errorf("uint32Opt(%q, %d) = nil error, want out-of-range error", c.name, c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("uint32Opt(%q, %d) error %q does not mention option name", c.name, c.in, err.Error())
		}
	}
}
