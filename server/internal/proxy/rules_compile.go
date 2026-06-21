package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// CompileRules serializes a list of RoutingRules into a compiled binary rule-set database file.
func CompileRules(rules []RoutingRule, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)

	// 1. Magic Header "LMRD" (LumiNet Rule Database)
	if _, err := writer.Write([]byte("LMRD")); err != nil {
		return err
	}

	// 2. Version 0x0001
	if err := binary.Write(writer, binary.BigEndian, uint16(1)); err != nil {
		return err
	}

	// 3. Count of rules
	if err := binary.Write(writer, binary.BigEndian, uint32(len(rules))); err != nil {
		return err
	}

	for _, rule := range rules {
		// DomainSuffix count & values
		if err := writeStringSlice(writer, rule.DomainSuffix); err != nil {
			return err
		}

		// DomainKeyword count & values
		if err := writeStringSlice(writer, rule.DomainKeyword); err != nil {
			return err
		}

		// IPRanges count & values
		if err := writeIPRanges(writer, rule.IPRanges); err != nil {
			return err
		}

		// OutboundTag
		if err := writeString(writer, rule.OutboundTag); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// LoadCompiledRules deserializes and loads a RulesRouter from a compiled binary database file.
func LoadCompiledRules(inputPath string) (*RulesRouter, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	// Read magic
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, err
	}
	if string(magic) != "LMRD" {
		return nil, errors.New("invalid rule database magic signature")
	}

	// Read version
	var version uint16
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, fmt.Errorf("unsupported rule database version: %d", version)
	}

	// Read rules count
	var rulesCount uint32
	if err := binary.Read(reader, binary.BigEndian, &rulesCount); err != nil {
		return nil, err
	}

	rules := make([]RoutingRule, rulesCount)
	for i := uint32(0); i < rulesCount; i++ {
		suffixes, err := readStringSlice(reader)
		if err != nil {
			return nil, err
		}

		keywords, err := readStringSlice(reader)
		if err != nil {
			return nil, err
		}

		ipRanges, err := readIPRanges(reader)
		if err != nil {
			return nil, err
		}

		tag, err := readString(reader)
		if err != nil {
			return nil, err
		}

		rules[i] = RoutingRule{
			DomainSuffix:  suffixes,
			DomainKeyword: keywords,
			IPRanges:      ipRanges,
			OutboundTag:   tag,
		}
	}

	router := &RulesRouter{Rules: rules}
	return router, nil
}

// LoadGeoIPRules reads a text/binary GeoIP CIDR database and extracts IP networks matching the country code.
// Format can be text lines: "CN,1.0.1.0/24"
func LoadGeoIPRules(dbPath string, countryCode string) ([]*net.IPNet, error) {
	// Audit check: All domain and IP matching routines are executed locally
	// to prevent DNS query leak tracking to public resolvers.
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matched []*net.IPNet
	scanner := bufio.NewScanner(f)
	target := strings.ToUpper(countryCode)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) == 2 && strings.ToUpper(parts[0]) == target {
			_, ipNet, err := net.ParseCIDR(parts[1])
			if err == nil {
				matched = append(matched, ipNet)
			}
		}
	}

	return matched, scanner.Err()
}

// WasmRuleRunner implements simulated execution of rules compiled into WebAssembly bytecode,
// ensuring strict execution timeouts to prevent engine freezing.
type WasmRuleRunner struct {
	bytecode []byte
}

// NewWasmRuleRunner initializes a simulated Wazero WASM VM runner.
func NewWasmRuleRunner(bytecode []byte) *WasmRuleRunner {
	return &WasmRuleRunner{bytecode: bytecode}
}

// Match evaluates rules routing using a simulated WASM VM script execution under strict timeout.
func (r *WasmRuleRunner) Match(ctx context.Context, host string, ip net.IP) (string, error) {
	// Strict timeout check: Verify if caller's context already expired
	if err := ctx.Err(); err != nil {
		return "", err
	}

	ch := make(chan string, 1)
	go func() {
		// Simulate computation time of rule logic
		time.Sleep(2 * time.Millisecond)

		// Rule routing logic simulation
		if strings.HasSuffix(host, ".cn") {
			ch <- "direct"
			return
		}
		ch <- "proxy"
	}()

	select {
	case <-ctx.Done():
		return "", errors.New("WASM VM execution timeout exceeded")
	case tag := <-ch:
		return tag, nil
	}
}

// Serialization Helpers
func writeString(w io.Writer, s string) error {
	data := []byte(s)
	if err := binary.Write(w, binary.BigEndian, uint16(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readString(r io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeStringSlice(w io.Writer, slice []string) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(slice))); err != nil {
		return err
	}
	for _, s := range slice {
		if err := writeString(w, s); err != nil {
			return err
		}
	}
	return nil
}

func readStringSlice(r io.Reader) ([]string, error) {
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	slice := make([]string, count)
	for i := uint32(0); i < count; i++ {
		s, err := readString(r)
		if err != nil {
			return nil, err
		}
		slice[i] = s
	}
	return slice, nil
}

func writeIPRanges(w io.Writer, ranges []*net.IPNet) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(ranges))); err != nil {
		return err
	}
	for _, r := range ranges {
		cidr := r.String()
		if err := writeString(w, cidr); err != nil {
			return err
		}
	}
	return nil
}

func readIPRanges(r io.Reader) ([]*net.IPNet, error) {
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	ranges := make([]*net.IPNet, count)
	for i := uint32(0); i < count; i++ {
		cidr, err := readString(r)
		if err != nil {
			return nil, err
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ranges[i] = ipNet
	}
	return ranges, nil
}
