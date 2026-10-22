package scanner

import (
	"testing"
)

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", ""}
	expected := []string{"a", "b", "c"}
	result := uniqueStrings(input)
	if len(result) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	}
}

func TestDeduplicateFindings(t *testing.T) {
	findings := []Finding{
		{Tool: "nuclei", Name: "test", Target: "example.com", Severity: "high"},
		{Tool: "nuclei", Name: "test", Target: "example.com", Severity: "high"},
		{Tool: "nikto", Name: "test2", Target: "example.com", Severity: "medium"},
	}
	result := deduplicateFindings(findings)
	if len(result) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(result))
	}
}

func TestExtractJSON(t *testing.T) {
	jsonStr := `{"host":"example.com","info":{"severity":"high","name":"Test"}}`
	host := extractJSON(jsonStr, "host")
	severity := extractJSON(jsonStr, "info.severity")
	name := extractJSON(jsonStr, "info.name")

	if host != "example.com" {
		t.Errorf("Expected host=example.com, got %s", host)
	}
	if severity != "high" {
		t.Errorf("Expected severity=high, got %s", severity)
	}
	if name != "Test" {
		t.Errorf("Expected name=Test, got %s", name)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "http___example.com"},
		{"example.com:8080", "example.com_8080"},
		{"path/to/file", "path_to_file"},
	}
	for _, tc := range cases {
		result := sanitizeFilename(tc.input)
		if result != tc.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestShouldRunModule(t *testing.T) {
	cases := []struct {
		selectedModules []string
		moduleName      string
		expected        bool
	}{
		{nil, "subdomain", true},           // nil = all
		{[]string{}, "subdomain", false},   // empty = none
		{[]string{"subdomain"}, "subdomain", true},
		{[]string{"dns", "http"}, "subdomain", false},
		{[]string{"subdomain", "dns"}, "dns", true},
	}
	for _, tc := range cases {
		result := shouldRunModule(tc.selectedModules, tc.moduleName)
		if result != tc.expected {
			t.Errorf("shouldRunModule(%v, %q) = %v, want %v", tc.selectedModules, tc.moduleName, result, tc.expected)
		}
	}
}

func TestGetModuleNames(t *testing.T) {
	modules := GetModuleNames()
	expected := []string{
		"subdomain", "dns", "http", "ssl",
		"portscan", "tech", "dir", "url",
		"vuln", "nikto", "ssl-vuln",
	}
	if len(modules) != len(expected) {
		t.Errorf("Expected %d modules, got %d", len(expected), len(modules))
	}
	for i, m := range expected {
		if modules[i] != m {
			t.Errorf("Module %d: expected %s, got %s", i, m, modules[i])
		}
	}
}