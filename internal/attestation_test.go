package app

import "testing"

func TestExtractXFCCHash(t *testing.T) {
	tests := []struct {
		name string
		xfcc string
		want string
	}{
		{
			name: "empty string",
			xfcc: "",
			want: "",
		},
		{
			name: "single entry with Hash",
			xfcc: "Hash=abcd1234",
			want: "abcd1234",
		},
		{
			name: "multiple entries rightmost wins",
			xfcc: "Hash=aaaa1111,Hash=bbbb2222",
			want: "bbbb2222",
		},
		{
			name: "multiple entries rightmost has no Hash",
			xfcc: "Hash=aaaa1111,By=spiffe://example",
			want: "",
		},
		{
			name: "no Hash field",
			xfcc: "By=spiffe://cluster.local/ns/default;URI=spiffe://cluster.local/ns/default",
			want: "",
		},
		{
			name: "Hash with invalid hex odd length",
			xfcc: "Hash=abcde",
			want: "",
		},
		{
			name: "Hash with non-hex characters",
			xfcc: "Hash=zzzz1234",
			want: "",
		},
		{
			name: "standard Envoy format",
			xfcc: "By=spiffe://cluster.local/ns/default;Hash=abcd1234ef567890;URI=spiffe://cluster.local/sa/client",
			want: "abcd1234ef567890",
		},
		{
			name: "standard Envoy format multiple entries rightmost wins",
			xfcc: "By=spiffe://a;Hash=aaaa1111,By=spiffe://b;Hash=bbbb2222;URI=spiffe://b",
			want: "bbbb2222",
		},
		{
			name: "whitespace around fields",
			xfcc: " By=spiffe://example ; Hash=abcd1234 ; URI=spiffe://example ",
			want: "abcd1234",
		},
		{
			name: "whitespace around Hash in multiple entries",
			xfcc: "Hash=aaaa1111, Hash=bbbb2222 ",
			want: "bbbb2222",
		},
		{
			name: "Hash field with empty value",
			xfcc: "Hash=",
			want: "",
		},
		{
			name: "Hash field 64-char SHA-256 hex",
			xfcc: "Hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "Hash field 128-char hex at max length",
			xfcc: "Hash=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			want: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name: "Hash field exceeds 128 chars",
			xfcc: "Hash=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want: "",
		},
		{
			name: "multiple Hash fields in same entry uses first match",
			xfcc: "Hash=aabb1122;Hash=ccdd3344",
			want: "aabb1122",
		},
		{
			name: "Hash prefix as substring of another key",
			xfcc: "SomeHash=1234;Hash=aabb1122",
			want: "aabb1122",
		},
		{
			name: "only comma no Hash",
			xfcc: ",",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractXFCCHash(tt.xfcc)
			if got != tt.want {
				t.Errorf("extractXFCCHash(%q) = %q, want %q", tt.xfcc, got, tt.want)
			}
		})
	}
}

func TestIsValidHexFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "valid 64-char hex SHA-256",
			input: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			want:  true,
		},
		{
			name:  "valid 128-char hex at max length",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			want:  true,
		},
		{
			name:  "odd-length hex string",
			input: "abcde",
			want:  false,
		},
		{
			name:  "non-hex characters",
			input: "zzzzzzzz",
			want:  false,
		},
		{
			name:  "mixed valid and invalid hex chars",
			input: "abcd12gh",
			want:  false,
		},
		{
			name:  "exceeds 128 chars",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want:  false,
		},
		{
			name:  "short valid hex",
			input: "abcdef",
			want:  true,
		},
		{
			name:  "two char hex",
			input: "ff",
			want:  true,
		},
		{
			name:  "uppercase hex",
			input: "ABCDEF0123456789",
			want:  true,
		},
		{
			name:  "mixed case hex",
			input: "aAbBcCdDeEfF",
			want:  true,
		},
		{
			name:  "single char not valid hex decode",
			input: "a",
			want:  false,
		},
		{
			name:  "spaces in hex",
			input: "ab cd",
			want:  false,
		},
		{
			name:  "exactly 129 chars",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want:  false,
		},
		{
			name:  "130 chars even length still too long",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("isValidHexFingerprint(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
