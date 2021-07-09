package xorfilter

import (
	"math"
)

// Xor16 offers a false-positive probability < 20/1,000,000
type Xor16 struct {
	XorFilterCommon
	Fingerprints []uint16
}

// Populate16 creates an xor filter with approx 16 bits per element.
func Populate16(keys []uint64) (*Xor16, error) {
	var bld Builder
	return bld.Populate16(keys)
}

// Contains tell you whether the key is likely part of the set
func (filter *Xor16) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := uint16(fingerprint(hash))
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.BlockLength)
	h1 := reduce(r1, filter.BlockLength) + filter.BlockLength
	h2 := reduce(r2, filter.BlockLength) + 2*filter.BlockLength
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2])
}

func (filter *Xor16) allocate(size int) {
	capacity := 32 + uint32(math.Ceil(1.23*float64(size)))
	capacity = capacity / 3 * 3 // round it down to a multiple of 3

	// slice capacity defaults to length
	filter.Fingerprints = make([]uint16, capacity)
	filter.BlockLength = capacity / 3
}

// Populate16 creates an xor filter with approx 16 bits per element.
func (bld *Builder) Populate16(keys []uint64) (*Xor16, error) {
	size := len(keys)
	filter := new(Xor16)
	filter.allocate(size)

	stack, err := bld.populateCommon(keys, &filter.XorFilterCommon)
	if err != nil {
		return nil, err
	}

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint16(fingerprint(ki.hash))
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
