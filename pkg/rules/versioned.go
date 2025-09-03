package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
	"gopkg.in/yaml.v2"
)

var (
	// Common CloudTrail fields for validation
	knownTopLevelFields = map[string]bool{
		"additionalEventData": true,
		"awsRegion":           true,
		"errorCode":           true,
		"errorMessage":        true,
		"eventCategory":       true,
		"eventID":             true,
		"eventName":           true,
		"eventSource":         true,
		"eventTime":           true,
		"eventType":           true,
		"eventVersion":        true,
		"managementEvent":     true,
		"readOnly":            true,
		"recipientAccountId":  true,
		"requestID":           true,
		"requestParameters":   true,
		"resources":           true,
		"responseElements":    true,
		"serviceEventDetails": true,
		"sourceIPAddress":     true,
		"userAgent":           true,
		"userIdentity":        true,
	}

	// Known nested fields
	knownNestedFields = map[string]bool{
		"userIdentity.type":        true,
		"userIdentity.principalId": true,
		"userIdentity.arn":         true,
		"userIdentity.accountId":   true,
		"userIdentity.accessKeyId": true,
		"userIdentity.userName":    true,
		"userIdentity.sessionContext.attributes.mfaAuthenticated": true,
		"userIdentity.sessionContext.attributes.creationDate":     true,
		"userIdentity.sessionContext.sessionIssuer.type":          true,
		"userIdentity.sessionContext.sessionIssuer.principalId":   true,
		"userIdentity.sessionContext.sessionIssuer.arn":           true,
		"userIdentity.sessionContext.sessionIssuer.accountId":     true,
		"userIdentity.sessionContext.sessionIssuer.userName":      true,
		"requestParameters.roleName":                              true,
		"responseElements.role.arn":                               true,
		"responseElements.role.roleName":                          true,
		"responseElements.role.path":                              true,
	}
)

// VersionedConfiguration represents a versioned configuration
type VersionedConfiguration struct {
	Version string      `yaml:"version" validate:"required,semver"`
	Rules   []*Rule     `yaml:"rules" validate:"required,dive"`
	Meta    *ConfigMeta `yaml:"meta,omitempty"`
}

// ConfigMeta contains metadata about the configuration
type ConfigMeta struct {
	Description string            `yaml:"description,omitempty"`
	Author      string            `yaml:"author,omitempty"`
	CreatedAt   string            `yaml:"created_at,omitempty"`
	UpdatedAt   string            `yaml:"updated_at,omitempty"`
	Tags        []string          `yaml:"tags,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Rule    string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in %s (rule: %s): %s", e.Field, e.Rule, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// LoadVersioned loads a versioned configuration from string
func LoadVersioned(rawCfg string) (*VersionedConfiguration, error) {
	cfg := new(VersionedConfiguration)

	err := yaml.Unmarshal([]byte(rawCfg), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	if cfg.Version == "" {
		return nil, fmt.Errorf("configuration version is required")
	}

	return cfg, nil
}

// Validate performs comprehensive validation of the configuration
func (vc *VersionedConfiguration) Validate() error {
	// Use the validator library for struct validation
	validate := validator.New()

	// Register custom validators
	if err := validate.RegisterValidation("semver", ValidateSemver); err != nil {
		return err
	}
	if err := validate.RegisterValidation("is-regex", ValidateIsRegex); err != nil {
		return err
	}

	// Validate struct
	if err := validate.Struct(vc); err != nil {
		return err
	}

	// Additional custom validations
	var errors ValidationErrors

	// Validate rules
	if err := vc.validateRules(); err != nil {
		if validationErrs, ok := err.(ValidationErrors); ok {
			errors = append(errors, validationErrs...)
		} else {
			errors = append(errors, ValidationError{
				Field:   "rules",
				Rule:    "general",
				Message: err.Error(),
			})
		}
	}

	// Check for duplicate rule names
	if err := vc.checkDuplicateRuleNames(); err != nil {
		errors = append(errors, *err)
	}

	// Validate field paths
	if err := vc.validateFieldPaths(); err != nil {
		errors = append(errors, err...)
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// validateRules validates individual rules
func (vc *VersionedConfiguration) validateRules() error {
	var errors ValidationErrors

	for i, rule := range vc.Rules {
		// Check rule name
		if rule.Name == "" {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("rules[%d].name", i),
				Rule:    rule.Name,
				Message: "rule name cannot be empty",
			})
		}

		// Check matches
		if len(rule.Matches) == 0 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("rules[%d].matches", i),
				Rule:    rule.Name,
				Message: "rule must have at least one match",
			})
		}

		// Validate each match
		for j, match := range rule.Matches {
			if match.FieldName == "" {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("rules[%d].matches[%d].field_name", i, j),
					Rule:    rule.Name,
					Message: "field name cannot be empty",
				})
			}

			if match.Regex == "" {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("rules[%d].matches[%d].regex", i, j),
					Rule:    rule.Name,
					Message: "regex pattern cannot be empty",
				})
			}

			// Validate regex compilation
			if _, err := regexp.Compile(match.Regex); err != nil {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("rules[%d].matches[%d].regex", i, j),
					Rule:    rule.Name,
					Message: fmt.Sprintf("invalid regex pattern: %v", err),
				})
			}

			// Check for dangerous regex patterns
			if containsReDoSPattern(match.Regex) {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("rules[%d].matches[%d].regex", i, j),
					Rule:    rule.Name,
					Message: "potentially dangerous regex pattern detected (ReDoS vulnerability)",
				})
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// checkDuplicateRuleNames checks for duplicate rule names
func (vc *VersionedConfiguration) checkDuplicateRuleNames() *ValidationError {
	seen := make(map[string]int)

	for i, rule := range vc.Rules {
		if prevIndex, exists := seen[rule.Name]; exists {
			return &ValidationError{
				Field:   fmt.Sprintf("rules[%d].name", i),
				Rule:    rule.Name,
				Message: fmt.Sprintf("duplicate rule name (also at index %d)", prevIndex),
			}
		}
		seen[rule.Name] = i
	}

	return nil
}

// validateFieldPaths validates that field paths follow expected patterns
func (vc *VersionedConfiguration) validateFieldPaths() ValidationErrors {
	var errors ValidationErrors

	for i, rule := range vc.Rules {
		for j, match := range rule.Matches {
			field := match.FieldName

			// Check if it's a known field
			if !knownTopLevelFields[field] && !knownNestedFields[field] {
				// Check if it starts with a known top-level field
				parts := strings.Split(field, ".")
				if len(parts) > 0 && !knownTopLevelFields[parts[0]] {
					log.Warn().
						Str("field", field).
						Str("rule", rule.Name).
						Msg("unknown CloudTrail field path (may be valid for custom events)")
				}
			}

			// Validate field path syntax
			if !isValidFieldPath(field) {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("rules[%d].matches[%d].field_name", i, j),
					Rule:    rule.Name,
					Message: fmt.Sprintf("invalid field path syntax: %s", field),
				})
			}
		}
	}

	return errors
}

// isValidFieldPath checks if a field path has valid syntax
func isValidFieldPath(path string) bool {
	// Field paths should be alphanumeric with dots, underscores, and hyphens
	validPath := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.\-]*$`)

	// Check overall pattern
	if !validPath.MatchString(path) {
		return false
	}

	// Check that dots are not consecutive or at the start/end
	if strings.Contains(path, "..") || strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") {
		return false
	}

	return true
}

// ValidateSemver validates semantic versioning
func ValidateSemver(fl validator.FieldLevel) bool {
	version := fl.Field().String()
	// Simple semver regex - can be made more strict if needed
	semverRegex := regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$`)
	return semverRegex.MatchString(version)
}

// ToConfiguration converts VersionedConfiguration to Configuration
func (vc *VersionedConfiguration) ToConfiguration() *Configuration {
	return &Configuration{
		Rules: vc.Rules,
	}
}

// DryRun performs a dry run of the configuration against sample events
func (vc *VersionedConfiguration) DryRun(sampleEvents []map[string]any) (*DryRunResult, error) {
	result := &DryRunResult{
		TotalEvents:   len(sampleEvents),
		RuleHits:      make(map[string]int),
		FilteredCount: 0,
	}

	// Prepare cached configuration for performance
	cachedCfg, err := PrepareConfiguration(vc.ToConfiguration())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare configuration: %w", err)
	}

	// Process each event
	for _, event := range sampleEvents {
		match, dropEvent, err := cachedCfg.EvalRules(event)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rules: %w", err)
		}

		if match {
			result.FilteredCount++
			result.RuleHits[dropEvent.RuleName]++
		}
	}

	result.PassedCount = result.TotalEvents - result.FilteredCount
	result.FilterRate = float64(result.FilteredCount) / float64(result.TotalEvents)

	return result, nil
}

// DryRunResult contains the results of a configuration dry run
type DryRunResult struct {
	TotalEvents   int
	FilteredCount int
	PassedCount   int
	FilterRate    float64
	RuleHits      map[string]int
}

// ExportConfiguration exports the configuration in different formats
func (vc *VersionedConfiguration) Export(format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "yaml", "yml":
		return yaml.Marshal(vc)
	case "json":
		// Convert to JSON-friendly structure
		type jsonExport struct {
			Version string           `json:"version"`
			Meta    *ConfigMeta      `json:"meta,omitempty"`
			Rules   []map[string]any `json:"rules"`
		}

		export := jsonExport{
			Version: vc.Version,
			Meta:    vc.Meta,
			Rules:   make([]map[string]any, len(vc.Rules)),
		}

		for i, rule := range vc.Rules {
			matches := make([]map[string]string, len(rule.Matches))
			for j, match := range rule.Matches {
				matches[j] = map[string]string{
					"field_name": match.FieldName,
					"regex":      match.Regex,
				}
			}

			export.Rules[i] = map[string]any{
				"name":    rule.Name,
				"matches": matches,
			}
		}

		// Use our JSON encoder
		return json.Marshal(export)

	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}
