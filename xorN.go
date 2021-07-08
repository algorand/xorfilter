package xorfilter

import (
	"math"
)

// XorN offers a configurable false-positive probability
type XorN struct {
	XorFilterCommon

	// Bits in 9..32
	Bits int

	// Fingerprints should be serialized as keeping the low XorN.Bits of each entry
	Fingerprints []uint32
}

// PopulateN creates an xor filter with tunable number of bits per element.
func PopulateN(keys []uint64, bits int) (*XorN, error) {
	var bld Builder
	return bld.PopulateN(keys, bits)
}

func (filter *XorN) mask() uint32 {
	return uint32(0x00000000ffffffff >> (32 - filter.Bits))
}

// Contains tell you whether the key is likely part of the set
func (filter *XorN) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	mask := filter.mask()
	f := uint32(fingerprint(hash)) & mask
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.BlockLength)
	h1 := reduce(r1, filter.BlockLength) + filter.BlockLength
	h2 := reduce(r2, filter.BlockLength) + 2*filter.BlockLength
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2])
}

func (filter *XorN) allocate(size int) {
	capacity := 32 + uint32(math.Ceil(1.23*float64(size)))
	capacity = capacity / 3 * 3 // round it down to a multiple of 3

	// slice capacity defaults to length
	filter.Fingerprints = make([]uint32, capacity)
	filter.BlockLength = capacity / 3
}

// PopulateN creates an xor filter with tunable number of bits per element.
func (bld *Builder) PopulateN(keys []uint64, bits int) (*XorN, error) {
	size := len(keys)
	filter := new(XorN)
	filter.Bits = bits
	filter.allocate(size)

	stack, err := bld.populateCommon(keys, &filter.XorFilterCommon)
	if err != nil {
		return nil, err
	}

	mask := filter.mask()

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint32(fingerprint(ki.hash)) & mask
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
