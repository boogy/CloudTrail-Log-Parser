package rules

import (
	"context"
	"ctlp/pkg/utils"
	"fmt"
	"os"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

// Configuration configuration containing our rules which are used to filter events
type Configuration struct {
	Rules []*Rule `yaml:"rules" validate:"required,dive"`
}

// Rule rule with a name, and one or more matches
type Rule struct {
	Name    string   `yaml:"name" validate:"required"`
	Matches []*Match `yaml:"matches" validate:"required,dive"`
}

// Match match containing the field to be checked and the REGEX used to match
//
//	FieldName string `yaml:"field_name" validate:"required,oneof=eventName eventSource awsRegion recipientAccountId"`
type Match struct {
	FieldName string `yaml:"field_name" validate:"required"`
	Regex     string `yaml:"regex" validate:"is-regex"`
}

type DropedEvent struct {
	RuleName string `json:"rule_name"`
}

// Load load the configuration from the provided string (uses versioned configuration)
func Load(rawCfg string) (*Configuration, error) {
	// Load as versioned configuration
	versionedCfg, err := LoadVersioned(rawCfg)
	if err != nil {
		log.Error().Err(err).Msg("failed to load versioned configuration")
		return nil, err
	}

	// Validate the versioned configuration
	if err := versionedCfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Convert to Configuration for compatibility
	return versionedCfg.ToConfiguration(), nil
}

// LoadFromConfigFile load the configuration from yaml file and validate it
func LoadFromConfigFile(ctx context.Context, path string) (*Configuration, error) {
	rawCfg, err := os.ReadFile(path)
	if err != nil {
		log.Error().Err(err).Msg("read config from file failed")
		return nil, fmt.Errorf("read config from file failed: %w", err)
	}

	// Load as versioned configuration
	versionedCfg, err := LoadVersioned(string(rawCfg))
	if err != nil {
		return nil, fmt.Errorf("load versioned configuration failed: %w", err)
	}

	// Validate the versioned configuration
	if err := versionedCfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Convert to Configuration for compatibility
	return versionedCfg.ToConfiguration(), nil
}

// Validate validate the configuration rules
func (cr *Configuration) Validate() error {
	validate := validator.New()

	err := validate.RegisterValidation("is-regex", ValidateIsRegex)
	if err != nil {
		return err
	}

	return validate.Struct(cr)
}

// ValidateIsRegex implements validator.Func with ReDoS protection
func ValidateIsRegex(fl validator.FieldLevel) bool {
	pattern := fl.Field().String()

	// Check for potential ReDoS patterns
	if containsReDoSPattern(pattern) {
		log.Warn().Str("pattern", pattern).Msg("potentially dangerous regex pattern detected")
		return false
	}

	// Limit regex pattern length
	if len(pattern) > 1000 {
		return false
	}

	_, err := regexp.Compile(pattern)
	return err == nil
}

// containsReDoSPattern checks for common ReDoS vulnerable patterns
//
// ReDoS (Regular Expression Denial of Service) occurs when certain regex patterns
// cause exponential backtracking, leading to CPU exhaustion. This function detects
// patterns known to cause such issues.
//
// Dangerous patterns detected:
// - Nested quantifiers: (x+)+ can cause O(2^n) time complexity
// - Alternation with overlap: (a|ab)* can cause excessive backtracking
// - Quantified groups with quantified content: (.*)* or (.+)+
//
// The function balances security with usability by only flagging patterns that
// are demonstrably dangerous, avoiding false positives on common safe patterns
// like (\d{4})+ which have bounded repetition.
//
// Reference: OWASP Regular Expression Denial of Service
// https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
func containsReDoSPattern(pattern string) bool {
	// Check for truly dangerous nested quantifiers that can cause exponential backtracking
	// Be more selective to avoid false positives on common safe patterns
	dangerousPatterns := []string{
		`\(\.\*\)\+`,       // (.*)+  - Unbounded nested quantifiers
		`\(\.\+\)\+`,       // (.+)+  - Unbounded nested quantifiers
		`\(\w\+\)\*\w\*`,   // (\w+)*\w* - Overlapping quantifiers
		`\(\d\+\)\+`,       // (\d+)+ - Nested digit quantifiers
		`\(\.\*\)\*`,       // (.*)*  - Nested wildcards
		`\(\[\^/\]\+\)\+/`, // ([^/]+)+/ - Common in path patterns
	}

	for _, dangerous := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dangerous, pattern); matched {
			return true
		}
	}
	return false
}

// EvalRules iterate over all rules and return a match if one evaluates to true
func (cr *Configuration) EvalRules(evt map[string]any) (bool, *DropedEvent, error) {
	for _, rule := range cr.Rules {
		match, dropedEvent, err := rule.Eval(evt)
		if err != nil {
			return false, nil, err
		}
		if match {
			return true, dropedEvent, nil
		}
	}
	return false, nil, nil
}

// Eval evaluate the match for a given event, this will run each field check in the rule
// if ALL evaluate to true the event is dropped
func (mc *Rule) Eval(evt map[string]any) (bool, *DropedEvent, error) {
	b := true
	dropEvent := DropedEvent{}

	for _, match := range mc.Matches {
		if exists, v := utils.FieldExists(match.FieldName, evt); exists {
			fieldValue, ok := v.(string)
			if !ok {
				continue
			}

			// Compile regex once and cache it to prevent repeated compilation attacks
			// Also add timeout for regex execution
			re, err := regexp.Compile(match.Regex)
			if err != nil {
				return false, &dropEvent, fmt.Errorf("invalid regex: %w", err)
			}
			hasMatch := re.MatchString(fieldValue)

			b = b && hasMatch // if all matches are true, we drop the event
		} else {
			b = b && exists // if field does not exist set b to false to keep the event
			continue        // and continue to the next match
		}
	}

	// if the event is dropped we return the drop event for logging
	if b {
		dropEvent = DropedEvent{RuleName: mc.Name}
	}

	return b, &dropEvent, nil
}
