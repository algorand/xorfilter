package xorfilter

import (
	"math"
)

// Xor32 holds an xorfilter with approximately 32 bits per element and about one in a billion false positives.
type Xor32 struct {
	XorFilterCommon
	Fingerprints []uint32
}

// Populate32 creates an xor filter with approx 32 bits per element.
func Populate32(keys []uint64) (*Xor32, error) {
	var bld Builder
	return bld.Populate32(keys)
}

// Contains tell you whether the key is likely part of the set
func (filter *Xor32) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := uint32(fingerprint(hash))
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.BlockLength)
	h1 := reduce(r1, filter.BlockLength) + filter.BlockLength
	h2 := reduce(r2, filter.BlockLength) + 2*filter.BlockLength
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2])
}

func (filter *Xor32) allocate(size int) {
	capacity := 32 + uint32(math.Ceil(1.23*float64(size)))
	capacity = capacity / 3 * 3 // round it down to a multiple of 3

	// slice capacity defaults to length
	filter.Fingerprints = make([]uint32, capacity)
	filter.BlockLength = capacity / 3
}

// Populate32 creates an xor filter with approx 32 bits per element.
func (bld *Builder) Populate32(keys []uint64) (*Xor32, error) {
	size := len(keys)
	filter := new(Xor32)
	filter.allocate(size)

	stack, err := bld.populateCommon(keys, &filter.XorFilterCommon)
	if err != nil {
		return nil, err
	}

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint32(fingerprint(ki.hash))
		if ki.index < filter.BlockLength {
			val ^= filter.Fingerprints[filter.geth1(ki.hash)+filter.BlockLength] ^ filter.Fingerprints[filter.geth2(ki.hash)+2*filter.BlockLength]
		} else if ki.index < 2*filter.BlockLength {
			val ^= filter.Fingerprints[filter.geth0(ki.hash)] ^ filter.Fingerprints[filter.geth2(ki.hash)+2*filter.BlockLength]
		} else {
			val ^= filter.Fingerprints[filter.geth0(ki.hash)] ^ filter.Fingerprints[filter.geth1(ki.hash)+filter.BlockLength]
		}
		filter.Fingerprints[ki.index] = val
	}
	return filter, nil
}
