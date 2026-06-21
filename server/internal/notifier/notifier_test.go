package notifier

import "testing"

func TestPsEscapeDoubleQuoted(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "hello \"world\"",
			expected: "hello `\"world`\"",
		},
		{
			input:    "test `backtick`",
			expected: "test ``backtick``",
		},
		{
			input:    "normal string",
			expected: "normal string",
		},
	}

	for _, tt := range tests {
		got := psEscapeDoubleQuoted(tt.input)
		if got != tt.expected {
			t.Errorf("psEscapeDoubleQuoted(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestAsEscapeDoubleQuoted(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "hello \"world\"",
			expected: "hello \\\"world\\\"",
		},
		{
			input:    "path\\to\\file",
			expected: "path\\\\to\\\\file",
		},
		{
			input:    "backslash \\ and quote \" test",
			expected: "backslash \\\\ and quote \\\" test",
		},
	}

	for _, tt := range tests {
		got := asEscapeDoubleQuoted(tt.input)
		if got != tt.expected {
			t.Errorf("asEscapeDoubleQuoted(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
