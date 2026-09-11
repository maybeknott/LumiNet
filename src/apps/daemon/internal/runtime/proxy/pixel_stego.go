package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"io"
	"net"
	"os"
)

const (
	maxPixelStegoPNGBytes  = 16 * 1024 * 1024
	maxPixelStegoDimension = 4096
	maxPixelStegoPixels    = 4 * 1024 * 1024
	maxPixelStegoPayload   = (maxPixelStegoPixels - 32) / 8
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

func validatePixelStegoDimensions(width, height int) error {
	if width <= 0 || height <= 0 {
		return errors.New("invalid steganographic image dimensions")
	}
	if width > maxPixelStegoDimension || height > maxPixelStegoDimension {
		return fmt.Errorf("steganographic image dimensions exceed %dx%d limit", maxPixelStegoDimension, maxPixelStegoDimension)
	}
	// Division form avoids width*height integer overflow.
	if width > maxPixelStegoPixels/height {
		return fmt.Errorf("steganographic image exceeds %d-pixel decode budget", maxPixelStegoPixels)
	}
	return nil
}

// generateDefaultDecoy generates a deterministic gradient RGBA image of sufficient capacity.
func generateDefaultDecoy(dataLen int) (*image.RGBA, error) {
	if dataLen < 0 || dataLen > maxPixelStegoPayload {
		return nil, fmt.Errorf("PixelStego payload too large: %d > %d", dataLen, maxPixelStegoPayload)
	}
	requiredPixels := 32 + dataLen*8
	side := 64
	for side*side < requiredPixels {
		side *= 2
	}
	if err := validatePixelStegoDimensions(side, side); err != nil {
		return nil, err
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
	return img, nil
}

// loadDecoyImage attempts to load the decoy image path. If not found or invalid,
// it generates a bounded default decoy.
func loadDecoyImage(path string, requiredLen int) (*image.RGBA, error) {
	if requiredLen < 0 || requiredLen > maxPixelStegoPayload {
		return nil, fmt.Errorf("PixelStego payload too large: %d > %d", requiredLen, maxPixelStegoPayload)
	}
	if path == "" {
		return generateDefaultDecoy(requiredLen)
	}
	file, err := os.Open(path)
	if err != nil {
		return generateDefaultDecoy(requiredLen)
	}
	defer file.Close()

	cfg, _, err := image.DecodeConfig(io.LimitReader(file, maxPixelStegoPNGBytes+1))
	if err != nil || validatePixelStegoDimensions(cfg.Width, cfg.Height) != nil {
		return generateDefaultDecoy(requiredLen)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	img, _, err := image.Decode(io.LimitReader(file, maxPixelStegoPNGBytes+1))
	if err != nil {
		return generateDefaultDecoy(requiredLen)
	}

	rgba := convertToRGBA(img)
	requiredBits := (4 + requiredLen) * 8
	totalPixels := rgba.Bounds().Dx() * rgba.Bounds().Dy()
	if requiredBits > totalPixels {
		return generateDefaultDecoy(requiredLen)
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
	if len(b) > maxPixelStegoPayload {
		return 0, fmt.Errorf("PixelStego payload too large: %d > %d", len(b), maxPixelStegoPayload)
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
	if err := png.Encode(&buf, stegoImg); err != nil {
		return 0, err
	}

	pngBytes := buf.Bytes()
	if len(pngBytes) > maxPixelStegoPNGBytes {
		return 0, errors.New("encoded steganographic image exceeds wire-size budget")
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(pngBytes)))
	if _, err := io.Copy(c.Conn, bytes.NewReader(header[:])); err != nil {
		return 0, err
	}
	if _, err := io.Copy(c.Conn, bytes.NewReader(pngBytes)); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *PixelStegoConn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}

	pngLen := binary.BigEndian.Uint32(header[:])
	if pngLen == 0 {
		return 0, nil
	}
	if pngLen > maxPixelStegoPNGBytes {
		return 0, errors.New("oversized steganographic image frame received")
	}

	pngBytes := make([]byte, int(pngLen))
	if _, err := io.ReadFull(c.Conn, pngBytes); err != nil {
		return 0, err
	}

	// Decode only the PNG metadata first. This is the semantic resource gate: a
	// tiny compressed frame cannot force allocation of an enormous decoded image.
	cfg, err := png.DecodeConfig(bytes.NewReader(pngBytes))
	if err != nil {
		return 0, err
	}
	if err := validatePixelStegoDimensions(cfg.Width, cfg.Height); err != nil {
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
	if len(payload) > maxPixelStegoPayload {
		return 0, errors.New("decoded PixelStego payload exceeds resource budget")
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
	if len(data) > maxPixelStegoPayload {
		return nil, fmt.Errorf("PixelStego payload too large: %d > %d", len(data), maxPixelStegoPayload)
	}
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if err := validatePixelStegoDimensions(width, height); err != nil {
		return nil, err
	}
	totalPixels := width * height

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
	if err := validatePixelStegoDimensions(width, height); err != nil {
		return nil, err
	}
	totalPixels := width * height
	if totalPixels < 32 {
		return nil, errors.New("image too small to contain steganographic header")
	}

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
	if uint64(dataLen) > uint64(maxPixelStegoPayload) {
		return nil, errors.New("extracted data length exceeds PixelStego payload budget")
	}
	requiredPixels := uint64(32) + uint64(dataLen)*8
	if requiredPixels > uint64(totalPixels) {
		return nil, errors.New("extracted data length exceeds image capacity; corrupted steganographic data")
	}

	data := make([]byte, int(dataLen))
	dataIdx := 0
	bitIdx = 0
	for i := uint64(32); i < requiredPixels; i++ {
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
