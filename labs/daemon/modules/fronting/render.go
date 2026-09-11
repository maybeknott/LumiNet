package fronting

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func isDateContinuation(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	for _, wd := range []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"} {
		if strings.HasPrefix(s, wd) {
			return true
		}
	}
	return false
}

// RenderRawResponse converts a relay envelope back into raw HTTP response
// bytes, mirroring parse_relay_json: relay-level gzip is undone first, then the
// target Content-Encoding (when recognised) so the caller always receives plain
// bytes; hop-unsafe headers are dropped and Set-Cookie values are split.
func RenderRawResponse(env *RelayEnvelope, maxBodyBytes int) ([]byte, error) {
	if env.IsError() {
		return nil, fmt.Errorf("fronting: envelope carries error: %s", env.Error)
	}
	body, err := env.DecodeBody()
	if err != nil {
		return nil, err
	}

	// Target-level content encoding: decode only when confirmed so a passthrough
	// compressed body never reaches the browser labelled as plain text.
	decoded := false
	if enc := targetContentEncoding(env.Headers); enc != "" {
		switch strings.ToLower(enc) {
		case "gzip":
			if plain, err := gunzipBytes(body); err == nil {
				body, decoded = plain, true
			}
		case "deflate":
			if plain, ok := inflateRawOrZlib(body); ok {
				body, decoded = plain, true
			}
		}
	}
	if maxBodyBytes > 0 && len(body) > maxBodyBytes {
		return nil, fmt.Errorf("fronting: response exceeds cap (%d > %d bytes)", len(body), maxBodyBytes)
	}

	statusText := statusText(env.Status)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", env.Status, statusText)
	skip := map[string]struct{}{
		"transfer-encoding": {}, "connection": {}, "keep-alive": {}, "content-length": {},
	}
	if decoded {
		skip["content-encoding"] = struct{}{}
	}
	for key, value := range env.Headers {
		lower := strings.ToLower(key)
		if _, hop := skip[lower]; hop {
			continue
		}
		for _, item := range headerValues(value) {
			if lower == "set-cookie" {
				for _, cookie := range splitSetCookie(item) {
					fmt.Fprintf(&b, "%s: %s\r\n", key, cookie)
				}
				continue
			}
			fmt.Fprintf(&b, "%s: %s\r\n", key, item)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	return append([]byte(b.String()), body...), nil
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 206:
		return "Partial Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	default:
		return "OK"
	}
}

// headerValues normalises Apps Script multi-valued headers (JSON arrays or
// comma-joined single strings) into individual values.
func headerValues(value any) []string {
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, toString(item))
		}
		return out
	case []string:
		return v
	default:
		return []string{toString(value)}
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

func targetContentEncoding(headers map[string]any) string {
	for key, value := range headers {
		if strings.EqualFold(key, "content-encoding") {
			first := ""
			if vals := headerValues(value); len(vals) > 0 {
				first = vals[0]
			}
			return strings.TrimSpace(strings.ToLower(first))
		}
	}
	return ""
}

type readerErr struct {
	r io.Reader
	e error
}

func (re readerErr) Read(p []byte) (int, error) { return 0, re.e }

func zlibReader(data []byte, err *error) io.Reader {
	zr, zerr := zlib.NewReader(bytes.NewReader(data))
	if zerr != nil {
		*err = zerr
		return strings.NewReader("")
	}
	return zr
}

// splitSetCookie splits a single header value that may carry several cookies
// joined with ", " — but never splits Expires-style date commas. Mirrors
// split_set_cookie from relay_response.py.
func splitSetCookie(blob string) []string {
	if blob == "" {
		return nil
	}
	parts := strings.Split(blob, ",")
	out := make([]string, 0, len(parts))
	current := strings.TrimSpace(parts[0])
	flush := func() {
		if current != "" {
			out = append(out, strings.TrimSpace(current))
		}
	}
	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)
		// Date-attribute continuation looks like "21 Oct 2025 07:28:00 GMT":
		// leading digit or weekday token belongs to the previous cookie.
		if isDateContinuation(lower) {
			current += ", " + trimmed
			continue
		}
		flush()
		current = trimmed
	}
	flush()
	return out
}

func gunzipBytes(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

// inflateRawOrZlib tries zlib-wrapped then raw deflate streams, matching the
// ambiguity of a bare "deflate" Content-Encoding header.
func inflateRawOrZlib(data []byte) ([]byte, bool) {
	var zerr error
	if out, err := io.ReadAll(zlibReader(data, &zerr)); err == nil && zerr == nil {
		return out, true
	}
	raw := flate.NewReader(bytes.NewReader(data))
	if out, err := io.ReadAll(raw); err == nil {
		return out, true
	}
	return nil, false
}
