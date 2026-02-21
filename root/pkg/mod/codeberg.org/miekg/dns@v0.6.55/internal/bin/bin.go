// Package bin pretty prints a byte slice.
package bin

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns/internal/ddd"
)

// Dump dumps the slice p in a way to help debugging DNS wire-format.
// Got used to reading decimal [192 12] is a pointer etc., so that's being used here.
// If the optional off is given this is used as an offset in the buffer.
//
// Output looks like:
//
//	    80
//		        0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15       0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
//
//		 0   | 007 101 120 097 109 112 108 101 000 000 250 000 255 000 000 000  |  007   e   x   a   m   p   l   e 000 000 250 000 255 000 000 000
//		16   | 000 000 061 011 104 109 097 099 045 115 104 097 050 053 054 000  |  000 000 061 011   h   m   a   c 045   s   h   a   2   5   6 000
//		32   | 000 000 104 164 006 221 000 255 000 032 005 003 084 048 105 165  |  000 000   h 164 006 221 000 255 000 032 005 003   T   0   i 165
//		48   | 027 037 157 115 234 167 019 146 176 044 217 119 200 195 242 213  |  027 037 157   s 234 167 019 146 176 044 217   w 200 195 242 213
//		64   | 186 251 188 127 016 138 199 028 029 021 000 003 000 000 000 000  |  186 251 188 127 016 138 199 028 029 021 000 003 000 000 000 000
//
// Usually called as: t.Logf("\n%s\n", bin.Dump(buf))
func Dump(p []byte, off ...int) string {
	if len(p) == 0 {
		return ""
	}
	of := 0
	if len(off) > 0 {
		of = off[0]
	}

	const N = 16
	dump := strings.Builder{}
	fmt.Fprintf(&dump, "% 5d\t", len(p[of:]))
	for i := range N {
		fmt.Fprintf(&dump, "% 4d", i)
	}
	dump.WriteString("    ")
	for i := range N {
		fmt.Fprintf(&dump, "% 4d", i)
	}
	dump.WriteByte('\n')
	dump.WriteByte('\n')

	row := 0
	plus := 0
	if of > 0 {
		plus = (of / N) * N
	}

	sb := strings.Builder{}
	for i := 0; i*N < len(p); i++ {
		a, b := i*N, (i+1)*N
		if b > len(p) {
			b = len(p)
		}

		line := p[a:b]
		sb.Reset()
		for j := range line {
			c := line[j]
			sb.WriteByte(' ')
			fmt.Fprintf(&sb, "%03d", c)
		}
		if len(line) < N { // pad out so the printable are aligned
			for range N - len(line) {
				sb.WriteByte(' ')
				sb.WriteString("   ")
			}
		}
		sb.WriteString("  | ")
		// printables
		for j := range line {
			c := line[j]
			sb.WriteByte(' ')
			if ddd.IsLetter(c) || ddd.IsDigit(c) {
				fmt.Fprintf(&sb, "%3s", string(c))
			} else {
				fmt.Fprintf(&sb, "%03d", c)
			}
		}

		fmt.Fprintf(&dump, "%5d\t|%s\n", row*N+plus, sb.String())
		row++
	}
	return dump.String()
}

// Bytes returns the bytes as a Go slice literal that can be used in source code.
func Bytes(p []byte, off ...int) string {
	if len(p) == 0 {
		return ""
	}
	of := 0
	if len(off) > 0 {
		of = off[0]
	}
	dump := strings.Builder{}
	dump.WriteString("[]byte{")
	fmt.Fprintf(&dump, "%d", p[of])
	for _, c := range p[of+1:] {
		fmt.Fprintf(&dump, ", %d", c)
	}

	dump.WriteByte('}')
	return dump.String()
}
