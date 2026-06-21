package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/png"
	_ "image/jpeg"
	"io"
	"net"
	"os"
)

// convertToRGBA converts any image to an RGBA pixel structure.
func convertToRGBA(img image.Image) *image.RGBA {
	if rgba, ok := img.(*image.RGBA); ok {
		return rgba
	}
	bounds := img.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			rgba.Set(x, y, img.At(x, y))
		}
	}
	return rgba
}

// generateDefaultDecoy generates a deterministic gradient RGBA image of sufficient capacity.
func generateDefaultDecoy(dataLen int) *image.RGBA {
	requiredPixels := 32 + dataLen*8
	side := 64
	for side*side < requiredPixels {
		side *= 2
	}
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8((x * 255) / side),
				G: uint8((y * 255) / side),
				B: uint8(((x + y) * 128) / side),
				A: 255,
			})
		}
	}
	return img
}

// loadDecoyImage attempts to load the decoy image path. If not found or too small, it generates a default.
func loadDecoyImage(path string, requiredLen int) (*image.RGBA, error) {
	if path == "" {
		return generateDefaultDecoy(requiredLen), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return generateDefaultDecoy(requiredLen), nil
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return generateDefaultDecoy(requiredLen), nil
	}

	rgba := convertToRGBA(img)
	requiredBits := (4 + requiredLen) * 8
	totalPixels := rgba.Bounds().Dx() * rgba.Bounds().Dy()
	if requiredBits > totalPixels {
		return generateDefaultDecoy(requiredLen), nil
	}

	return rgba, nil
}

// PixelStegoConn wraps a net.Conn to camouflage connection data inside LSB of PNG images.
type PixelStegoConn struct {
	net.Conn
	decoyPath string
	readBuf   bytes.Buffer
}

func NewPixelStegoConn(conn net.Conn, decoyPath string) *PixelStegoConn {
	return &PixelStegoConn{
		Conn:      conn,
		decoyPath: decoyPath,
	}
}

func (c *PixelStegoConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	rgba, err := loadDecoyImage(c.decoyPath, len(b))
	if err != nil {
		return 0, err
	}

	stegoImg, err := HideDataInImage(rgba, b)
	if err != nil {
		return 0, err
	}

	var buf bytes.Buffer
	err = png.Encode(&buf, stegoImg)
	if err != nil {
		return 0, err
	}

	pngBytes := buf.Bytes()
	totalLen := uint32(len(pngBytes))

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, totalLen)

	_, err = c.Conn.Write(header)
	if err != nil {
		return 0, err
	}

	n, err := c.Conn.Write(pngBytes)
	if err != nil {
		return 0, err
	}

	if n != len(pngBytes) {
		return 0, io.ErrShortWrite
	}

	return len(b), nil
}

func (c *PixelStegoConn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	header := make([]byte, 4)
	_, err := io.ReadFull(c.Conn, header)
	if err != nil {
		return 0, err
	}

	pngLen := binary.BigEndian.Uint32(header)
	if pngLen == 0 {
		return 0, nil
	}

	if pngLen > 16*1024*1024 {
		return 0, errors.New("oversized steganographic image frame received")
	}

	pngBytes := make([]byte, pngLen)
	_, err = io.ReadFull(c.Conn, pngBytes)
	if err != nil {
		return 0, err
	}

	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return 0, err
	}

	rgba := convertToRGBA(img)

	payload, err := ExtractDataFromImage(rgba)
	if err != nil {
		return 0, err
	}

	if len(payload) == 0 {
		return 0, nil
	}

	c.readBuf.Write(payload)
	return c.readBuf.Read(b)
}

// HideDataInImage encodes binary data inside the LSB (least significant bit) of image pixels' Red channel.
// It prepends a 4-byte big-endian length header to the data.
func HideDataInImage(img *image.RGBA, data []byte) (*image.RGBA, error) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	totalPixels := width * height

	// Prepend 4-byte length header
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	fullData := append(header, data...)

	requiredBits := len(fullData) * 8
	if requiredBits > totalPixels {
		return nil, errors.New("image too small to encode data")
	}

	dataIdx := 0
	bitIdx := 0

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if dataIdx >= len(fullData) {
				return img, nil
			}

			origColor := img.RGBAAt(x, y)
			bit := (fullData[dataIdx] >> bitIdx) & 1

			// Adjust Red channel LSB
			origColor.R = (origColor.R & 0xFE) | bit
			img.SetRGBA(x, y, origColor)

			bitIdx++
			if bitIdx >= 8 {
				bitIdx = 0
				dataIdx++
			}
		}
	}
	return img, nil
}

// ExtractDataFromImage extracts binary data hidden inside the LSB of image pixels' Red channel.
func ExtractDataFromImage(img *image.RGBA) ([]byte, error) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	totalPixels := width * height

	if totalPixels < 32 { // Need at least 32 pixels for the 4-byte length header
		return nil, errors.New("image too small to contain steganographic header")
	}

	// First, extract the 4-byte header (32 bits)
	header := make([]byte, 4)
	headerIdx := 0
	bitIdx := 0

	x := bounds.Min.X
	y := bounds.Min.Y

	for i := 0; i < 32; i++ {
		origColor := img.RGBAAt(x, y)
		bit := origColor.R & 1

		header[headerIdx] |= bit << bitIdx

		bitIdx++
		if bitIdx >= 8 {
			bitIdx = 0
			headerIdx++
		}

		x++
		if x >= bounds.Max.X {
			x = bounds.Min.X
			y++
		}
	}

	dataLen := binary.BigEndian.Uint32(header)
	if dataLen == 0 {
		return nil, nil
	}

	requiredPixels := 32 + int(dataLen)*8
	if requiredPixels > totalPixels {
		return nil, errors.New("extracted data length exceeds image capacity; corrupted steganographic data")
	}

	data := make([]byte, dataLen)
	dataIdx := 0
	bitIdx = 0

	for i := 32; i < requiredPixels; i++ {
		origColor := img.RGBAAt(x, y)
		bit := origColor.R & 1

		data[dataIdx] |= bit << bitIdx

		bitIdx++
		if bitIdx >= 8 {
			bitIdx = 0
			dataIdx++
		}

		x++
		if x >= bounds.Max.X {
			x = bounds.Min.X
			y++
		}
	}

	return data, nil
}
