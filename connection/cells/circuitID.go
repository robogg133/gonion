package cells

func MSB(n uint32) uint32 {
	n |= 0x80000000
	return n
}
