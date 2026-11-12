// mkicon draws the netshot icon and embeds it in the Windows executable,
// using the standard library only (no external resource compiler).
//
//	go run ./tools/mkicon        (from the project root)
//
// Writes:
//   - cmd/netshot/icon.png                  256x256, embedded as the GUI favicon
//   - cmd/netshot/rsrc_windows_amd64.syso   COFF resource object picked up by `go build`
//   - assets/icon.ico                       multi-size icon (16 to 256 px), for reference
//
// Design: blue rounded square, white browser window with a small network inside,
// amber screenshot crop marks around it.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

type rgba struct{ r, g, b, a float64 }

// canvas is a supersampled drawing surface; shapes use coordinates in [0,1].
type canvas struct {
	n   int
	pix []rgba
}

// blend paints color c over pixel (x, y).
func (cv *canvas) blend(x, y int, c rgba) {
	p := &cv.pix[y*cv.n+x]
	a := c.a
	p.r = c.r*a + p.r*(1-a)
	p.g = c.g*a + p.g*(1-a)
	p.b = c.b*a + p.b*(1-a)
	p.a = a + p.a*(1-a)
}

func (cv *canvas) fill(test func(x, y float64) bool, color func(x, y float64) rgba) {
	n := float64(cv.n)
	for py := 0; py < cv.n; py++ {
		for px := 0; px < cv.n; px++ {
			x, y := (float64(px)+0.5)/n, (float64(py)+0.5)/n
			if test(x, y) {
				cv.blend(px, py, color(x, y))
			}
		}
	}
}

func solid(c rgba) func(x, y float64) rgba { return func(float64, float64) rgba { return c } }

func inRoundRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r
}

func segDist(x, y, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(ax+t*dx-x, ay+t*dy-y)
}

func (cv *canvas) line(ax, ay, bx, by, w float64, c rgba) {
	cv.fill(func(x, y float64) bool { return segDist(x, y, ax, ay, bx, by) <= w/2 }, solid(c))
}

func (cv *canvas) circle(cx, cy, r float64, c rgba) {
	cv.fill(func(x, y float64) bool { return math.Hypot(x-cx, y-cy) <= r }, solid(c))
}

func hex(s string) rgba {
	var v [3]float64
	for i := 0; i < 3; i++ {
		n := 0
		for _, ch := range s[1+2*i : 3+2*i] {
			n *= 16
			if ch >= '0' && ch <= '9' {
				n += int(ch - '0')
			} else {
				n += int(ch|0x20-'a') + 10
			}
		}
		v[i] = float64(n) / 255
	}
	return rgba{v[0], v[1], v[2], 1}
}

// render draws the icon at the given pixel size.
func render(size int) *image.NRGBA {
	ss := 4
	if size <= 48 {
		ss = 8 // more supersampling keeps small sizes crisp
	}
	cv := &canvas{n: size * ss, pix: make([]rgba, size*ss*size*ss)}
	top, bottom := hex("#3b82f6"), hex("#1e3a8a")
	white, amber, blue, bar := hex("#ffffff"), hex("#fbbf24"), hex("#2563eb"), hex("#dbeafe")

	// Background: rounded square with vertical gradient
	cv.fill(func(x, y float64) bool { return inRoundRect(x, y, 0.02, 0.02, 0.98, 0.98, 0.22) },
		func(x, y float64) rgba {
			return rgba{top.r + (bottom.r-top.r)*y, top.g + (bottom.g-top.g)*y, top.b + (bottom.b-top.b)*y, 1}
		})

	// Browser window with title bar and three dots
	wx0, wy0, wx1, wy1 := 0.22, 0.27, 0.78, 0.73
	inWin := func(x, y float64) bool { return inRoundRect(x, y, wx0, wy0, wx1, wy1, 0.05) }
	cv.fill(inWin, solid(white))
	cv.fill(func(x, y float64) bool { return inWin(x, y) && y < wy0+0.085 }, solid(bar))
	for i, c := range []string{"#ef4444", "#f59e0b", "#22c55e"} {
		cv.circle(wx0+0.05+float64(i)*0.045, wy0+0.043, 0.016, hex(c))
	}

	// Network inside the window: three linked nodes
	nodes := [][2]float64{{0.35, 0.62}, {0.50, 0.44}, {0.65, 0.62}}
	for i := range nodes {
		a, b := nodes[i], nodes[(i+1)%len(nodes)]
		cv.line(a[0], a[1], b[0], b[1], 0.022, blue)
	}
	for _, n := range nodes {
		cv.circle(n[0], n[1], 0.045, blue)
		cv.circle(n[0], n[1], 0.022, white)
	}

	// Screenshot crop marks around the window
	m0, m1, l, w := 0.12, 0.88, 0.14, 0.045
	for _, c := range [][4]float64{{m0, m0, 1, 1}, {m1, m0, -1, 1}, {m0, m1, 1, -1}, {m1, m1, -1, -1}} {
		x, y, sx, sy := c[0], c[1], c[2], c[3]
		cv.line(x, y, x+sx*l, y, w, amber)
		cv.line(x, y, x, y+sy*l, w, amber)
	}

	// Downsample
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for dy := 0; dy < ss; dy++ {
				for dx := 0; dx < ss; dx++ {
					p := cv.pix[(y*ss+dy)*cv.n+x*ss+dx]
					r, g, b, a = r+p.r*p.a, g+p.g*p.a, b+p.b*p.a, a+p.a
				}
			}
			if a > 0 {
				img.SetNRGBA(x, y, color.NRGBA{uint8(r / a * 255), uint8(g / a * 255), uint8(b / a * 255),
					uint8(a / float64(ss*ss) * 255)})
			}
		}
	}
	return img
}

func encodePNG(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// encodeDIB returns the icon-format BMP (32-bit BGRA, bottom-up, followed by an empty AND mask).
func encodeDIB(img *image.NRGBA) []byte {
	n := img.Bounds().Dx()
	var buf bytes.Buffer
	le := binary.LittleEndian
	maskRow := ((n + 31) / 32) * 4
	binary.Write(&buf, le, struct {
		Size                          uint32
		Width, Height                 int32
		Planes, BitCount              uint16
		Compression, SizeImage        uint32
		XPels, YPels, ClrUsed, ClrImp int32
	}{40, int32(n), int32(2 * n), 1, 32, 0, uint32(n*n*4 + maskRow*n), 0, 0, 0, 0})
	for y := n - 1; y >= 0; y-- {
		for x := 0; x < n; x++ {
			c := img.NRGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	buf.Write(make([]byte, maskRow*n))
	return buf.Bytes()
}

type iconImage struct {
	size int
	data []byte
}

// writeICO writes a standard .ico file.
func writeICO(path string, icons []iconImage) {
	var buf bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&buf, le, [3]uint16{0, 1, uint16(len(icons))})
	offset := 6 + 16*len(icons)
	for _, ic := range icons {
		dim := uint8(ic.size % 256) // 0 means 256
		buf.Write([]byte{dim, dim, 0, 0})
		binary.Write(&buf, le, [2]uint16{1, 32})
		binary.Write(&buf, le, [2]uint32{uint32(len(ic.data)), uint32(offset)})
		offset += len(ic.data)
	}
	for _, ic := range icons {
		buf.Write(ic.data)
	}
	must(os.WriteFile(path, buf.Bytes(), 0o644))
}

// writeSyso writes a COFF object holding a .rsrc section with RT_ICON and RT_GROUP_ICON
// resources. The Go linker merges it into the executable automatically.
func writeSyso(path string, icons []iconImage) {
	const (
		rtIcon      = 3
		rtGroupIcon = 14
		lang        = 0x0409
		subdir      = 0x80000000
	)
	le := binary.LittleEndian
	n := len(icons)

	// Group icon payload (GRPICONDIR + entries pointing to RT_ICON ids 1..n)
	var group bytes.Buffer
	binary.Write(&group, le, [3]uint16{0, 1, uint16(n)})
	for i, ic := range icons {
		dim := uint8(ic.size % 256)
		group.Write([]byte{dim, dim, 0, 0})
		binary.Write(&group, le, [2]uint16{1, 32})
		binary.Write(&group, le, uint32(len(ic.data)))
		binary.Write(&group, le, uint16(i+1))
	}

	// Layout: root dir | RT_ICON dir | RT_GROUP_ICON dir | n+1 language dirs | n+1 data entries | payloads
	dirSize := func(entries int) int { return 16 + 8*entries }
	rootOff := 0
	iconDirOff := rootOff + dirSize(2)
	groupDirOff := iconDirOff + dirSize(n)
	langOff := groupDirOff + dirSize(1)
	dataEntryOff := langOff + (n+1)*dirSize(1)
	payloadOff := dataEntryOff + (n+1)*16

	payloads := append([][]byte{}, group.Bytes())
	for _, ic := range icons {
		payloads = append(payloads, ic.data)
	}
	// payload i: 0 = group, 1..n = icons
	payloadAt := make([]int, len(payloads))
	off := payloadOff
	for i, p := range payloads {
		payloadAt[i] = off
		off += (len(p) + 7) &^ 7
	}
	section := make([]byte, off)

	putDir := func(at int, ids []uint32, targets []uint32) {
		le.PutUint16(section[at+14:], uint16(len(ids)))
		for i := range ids {
			le.PutUint32(section[at+16+8*i:], ids[i])
			le.PutUint32(section[at+20+8*i:], targets[i])
		}
	}
	putDir(rootOff, []uint32{rtIcon, rtGroupIcon}, []uint32{subdir | uint32(iconDirOff), subdir | uint32(groupDirOff)})

	// Language dir k and data entry k: k = 0 for the group, 1..n for icons
	langDir := func(k int) int { return langOff + k*dirSize(1) }
	dataEntry := func(k int) int { return dataEntryOff + k*16 }
	ids := make([]uint32, n)
	targets := make([]uint32, n)
	for i := 0; i < n; i++ {
		ids[i] = uint32(i + 1)
		targets[i] = subdir | uint32(langDir(i+1))
	}
	putDir(iconDirOff, ids, targets)
	putDir(groupDirOff, []uint32{1}, []uint32{subdir | uint32(langDir(0))})

	var relocs []uint32 // offsets of OffsetToData fields, relocated as image-relative addresses
	for k := 0; k <= n; k++ {
		putDir(langDir(k), []uint32{lang}, []uint32{uint32(dataEntry(k))})
		le.PutUint32(section[dataEntry(k):], uint32(payloadAt[k]))
		le.PutUint32(section[dataEntry(k)+4:], uint32(len(payloads[k])))
		relocs = append(relocs, uint32(dataEntry(k)))
		copy(section[payloadAt[k]:], payloads[k])
	}

	// COFF file: header, one section header, raw data, relocations, symbol table, string table
	var out bytes.Buffer
	const headerSize, sectionHeaderSize, relocSize = 20, 40, 10
	rawPtr := headerSize + sectionHeaderSize
	relocPtr := rawPtr + len(section)
	symPtr := relocPtr + relocSize*len(relocs)
	binary.Write(&out, le, struct {
		Machine          uint16
		NumberOfSections uint16
		TimeDateStamp    uint32
		SymbolTable      uint32
		NumberOfSymbols  uint32
		OptHeaderSize    uint16
		Characteristics  uint16
	}{0x8664, 1, 0, uint32(symPtr), 1, 0, 0})
	binary.Write(&out, le, struct {
		Name                                 [8]byte
		VirtualSize, VirtualAddress, RawSize uint32
		RawPtr, RelocPtr, LinePtr            uint32
		NumRelocs, NumLines                  uint16
		Characteristics                      uint32
	}{[8]byte{'.', 'r', 's', 'r', 'c'}, 0, 0, uint32(len(section)), uint32(rawPtr), uint32(relocPtr), 0,
		uint16(len(relocs)), 0, 0x40000040}) // initialized data, readable
	out.Write(section)
	for _, r := range relocs {
		binary.Write(&out, le, r)         // offset in section
		binary.Write(&out, le, uint32(0)) // symbol 0 = the section itself
		binary.Write(&out, le, uint16(3)) // IMAGE_REL_AMD64_ADDR32NB
	}
	binary.Write(&out, le, struct {
		Name          [8]byte
		Value         uint32
		SectionNumber int16
		Type          uint16
		StorageClass  uint8
		NumAux        uint8
	}{[8]byte{'.', 'r', 's', 'r', 'c'}, 0, 1, 0, 3, 0}) // static symbol for the section
	binary.Write(&out, le, uint32(4)) // empty string table
	must(os.WriteFile(path, out.Bytes(), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var icons []iconImage
	var big *image.NRGBA
	for _, s := range []int{16, 24, 32, 48, 64, 128, 256} {
		img := render(s)
		if s == 256 {
			big = img
			icons = append(icons, iconImage{s, encodePNG(img)}) // PNG for 256 px, as Windows expects
		} else {
			icons = append(icons, iconImage{s, encodeDIB(img)})
		}
	}
	must(os.MkdirAll("assets", 0o755))
	must(os.WriteFile("cmd/netshot/icon.png", encodePNG(big), 0o644))
	writeICO("assets/icon.ico", icons)
	writeSyso("cmd/netshot/rsrc_windows_amd64.syso", icons)
}
