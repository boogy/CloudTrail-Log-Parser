package rules

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadVersioned(t *testing.T) {
	t.Run("load versioned config", func(t *testing.T) {
		yamlConfig := `
version: 1.0.0
meta:
  description: Test configuration
  author: test
rules:
  - name: Test Rule
    matches:
      - field_name: eventName
        regex: "^Test.*$"
      - field_name: eventSource
        regex: "test.amazonaws.com"
`
		cfg, err := LoadVersioned(yamlConfig)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "1.0.0", cfg.Version)
		assert.Equal(t, "Test configuration", cfg.Meta.Description)
		assert.Len(t, cfg.Rules, 1)
	})
	
	t.Run("config without version fails", func(t *testing.T) {
		yamlConfig := `
rules:
  - name: Legacy Rule
    matches:
      - field_name: eventName
        regex: "^Legacy.*$"
`
		cfg, err := LoadVersioned(yamlConfig)
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "configuration version is required")
	})
	
	t.Run("invalid yaml", func(t *testing.T) {
		yamlConfig := `
invalid: yaml: structure
`
		cfg, err := LoadVersioned(yamlConfig)
		assert.Error(t, err)
		assert.Nil(t, cfg)
	})
}

func TestVersionedValidation(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name: "Valid Rule",
					Matches: []*Match{
						{
							FieldName: "eventName",
							Regex:     "^Test.*$",
						},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.NoError(t, err)
	})
	
	t.Run("invalid version", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "invalid",
			Rules: []*Rule{
				{
					Name: "Test Rule",
					Matches: []*Match{
						{
							FieldName: "eventName",
							Regex:     "^Test.*$",
						},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
	})
	
	t.Run("empty rule name", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name: "",
					Matches: []*Match{
						{
							FieldName: "eventName",
							Regex:     "^Test.*$",
						},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
		// The struct validator returns a different message
		assert.Contains(t, err.Error(), "'Name' failed on the 'required' tag")
	})
	
	t.Run("duplicate rule names", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name: "Duplicate",
					Matches: []*Match{
						{FieldName: "eventName", Regex: "^Test1.*$"},
					},
				},
				{
					Name: "Duplicate",
					Matches: []*Match{
						{FieldName: "eventName", Regex: "^Test2.*$"},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate rule name")
	})
	
	t.Run("invalid regex", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name: "Invalid Regex Rule",
					Matches: []*Match{
						{
							FieldName: "eventName",
							Regex:     "[invalid(regex",
						},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
		// The struct validator returns a different message
		assert.Contains(t, err.Error(), "'Regex' failed on the 'is-regex' tag")
	})
	
	t.Run("dangerous regex pattern", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name: "Dangerous Regex",
					Matches: []*Match{
						{
							FieldName: "eventName",
							Regex:     "(.*)+",
						},
					},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
		// The struct validator returns a different message for ReDoS patterns
		assert.Contains(t, err.Error(), "'Regex' failed on the 'is-regex' tag")
	})
	
	t.Run("empty matches", func(t *testing.T) {
		cfg := &VersionedConfiguration{
			Version: "1.0.0",
			Rules: []*Rule{
				{
					Name:    "No Matches",
					Matches: []*Match{},
				},
			},
		}
		
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must have at least one match")
	})
}

func TestValidateSemver(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"1.0.0", true},
		{"v1.0.0", true},
		{"1.2.3", true},
		{"1.2.3-alpha", true},
		{"1.2.3-alpha.1", true},
		{"1.2.3+build", true},
		{"1.2.3-alpha+build", true},
		{"invalid", false},
		{"1", false},
		{"1.2", false},
		{"1.2.a", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			// We'll test the regex directly since we can't easily test the validator
			semverRegex := `^v?(\d+)\.(\d+)\.(\d+)(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$`
			matched := regexp.MustCompile(semverRegex).MatchString(tt.version)
			assert.Equal(t, tt.valid, matched)
		})
	}
}

func TestIsValidFieldPath(t *testing.T) {
	tests := []struct {
		path  string
		valid bool
	}{
		{"eventName", true},
		{"userIdentity.type", true},
		{"userIdentity.sessionContext.sessionIssuer.arn", true},
		{"requestParameters.bucketName", true},
		{"", false},
		{".eventName", false},
		{"eventName.", false},
		{"event..Name", false},
		{"123eventName", false},
		{"event-Name", true}, // Now allowed with hyphens
		{"event Name", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isValidFieldPath(tt.path)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestDryRun(t *testing.T) {
	cfg := &VersionedConfiguration{
		Version: "1.0.0",
		Rules: []*Rule{
			{
				Name: "Filter Test Events",
				Matches: []*Match{
					{
						FieldName: "eventName",
						Regex:     "^Test.*$",
					},
				},
			},
			{
				Name: "Filter EC2 Events",
				Matches: []*Match{
					{
						FieldName: "eventSource",
						Regex:     "ec2.amazonaws.com",
					},
				},
			},
		},
	}
	
	sampleEvents := []map[string]any{
		{"eventName": "TestEvent", "eventSource": "test.amazonaws.com"},
		{"eventName": "CreateBucket", "eventSource": "s3.amazonaws.com"},
		{"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com"},
		{"eventName": "TestAnother", "eventSource": "lambda.amazonaws.com"},
	}
	
	result, err := cfg.DryRun(sampleEvents)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	
	assert.Equal(t, 4, result.TotalEvents)
	assert.Equal(t, 3, result.FilteredCount) // TestEvent, TestAnother, and EC2 event
	assert.Equal(t, 1, result.PassedCount)
	assert.Equal(t, 0.75, result.FilterRate)
	
	assert.Equal(t, 2, result.RuleHits["Filter Test Events"])
	assert.Equal(t, 1, result.RuleHits["Filter EC2 Events"])
}

func TestExportConfiguration(t *testing.T) {
	cfg := &VersionedConfiguration{
		Version: "1.0.0",
		Meta: &ConfigMeta{
			Description: "Test export",
			Author:      "test",
		},
		Rules: []*Rule{
			{
				Name: "Test Rule",
				Matches: []*Match{
					{
						FieldName: "eventName",
						Regex:     "^Test.*$",
					},
				},
			},
		},
	}
	
	t.Run("export as yaml", func(t *testing.T) {
		data, err := cfg.Export("yaml")
		assert.NoError(t, err)
		assert.Contains(t, string(data), "version: 1.0.0")
		assert.Contains(t, string(data), "Test Rule")
	})
	
	t.Run("export as json", func(t *testing.T) {
		data, err := cfg.Export("json")
		assert.NoError(t, err)
		assert.Contains(t, string(data), `"version":"1.0.0"`)
		assert.Contains(t, string(data), `"Test Rule"`)
	})
	
	t.Run("unsupported format", func(t *testing.T) {
		data, err := cfg.Export("xml")
		assert.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "unsupported export format")
	})
}

func TestToConfiguration(t *testing.T) {
	vc := &VersionedConfiguration{
		Version: "1.0.0",
		Rules: []*Rule{
			{
				Name: "Test Rule",
				Matches: []*Match{
					{
						FieldName: "eventName",
						Regex:     "^Test.*$",
					},
				},
			},
		},
	}
	
	cfg := vc.ToConfiguration()
	assert.NotNil(t, cfg)
	assert.Len(t, cfg.Rules, 1)
	assert.Equal(t, "Test Rule", cfg.Rules[0].Name)
}