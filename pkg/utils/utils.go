package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

func Unmarshal(payload []byte, v any) bool {
	err := json.Unmarshal(payload, &v)
	return err == nil
}

func Marshal(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}
	return data, nil
}

func ReadFileContents(filepath string) (string, error) {
	// Security: Validate file path to prevent directory traversal
	if strings.Contains(filepath, "..") {
		return "", fmt.Errorf("invalid file path")
	}

	file, err := os.ReadFile(filepath)
	if err != nil {
		// Security: Don't expose full file path in error
		return "", fmt.Errorf("failed to read file")
	}
	return string(file), nil
}

// ContainsString checks if the slice has the contains a value.
func ContainsString(slice []string, contains string) bool {
	return slices.Contains(slice, contains)
}

func IsFieldPresent(field string, event map[string]any) (bool, any) {
	parts := strings.Split(field, ".") // Split the field into parts (if it's a nested field)
	currentMap := event

	// Traverse through nested maps
	for _, part := range parts {
		if value, ok := currentMap[part]; ok {
			// If the field exists, update the current map
			if nestedMap, isMap := value.(map[string]any); isMap {
				currentMap = nestedMap
			} else {
				// Field found, return its value
				return true, value
			}
		} else {
			// Field not found
			return false, nil
		}
	}

	// Field not found in the entire map
	return false, nil
}

func FieldExists(field string, event map[string]any) (bool, any) {
	path := strings.Split(field, ".")
	return findField(event, path)
}

func findField(obj map[string]any, path []string) (bool, any) {
	// Base case: if path is empty, return nil
	if len(path) == 0 {
		return false, nil // All parts processed, field not found
	}

	// Get the next field
	field := path[0]
	val, ok := obj[field]
	if !ok {
		return false, nil
	}

	// If the value is a nested map, continue searching
	if nested, isMap := val.(map[string]any); isMap {
		return findField(nested, path[1:])
	}

	// If the value is not a map and this is the last path element, return the value
	if len(path) == 1 {
		return true, val
	}

	return false, nil
}

func ExtractStringField(evt map[string]any, key string) string {
	value, found := evt[key]
	if !found {
		return "unknown"
	}

	strValue, ok := value.(string)
	if !ok {
		return "unknown"
	}
	return strValue
}

func InjectValueIntoContext(ctx context.Context, key, value any) context.Context {
	return context.WithValue(ctx, key, value)
}

func ReadTestEvents(filePath string) map[string]any {
	logger := log.With().Str("filePath", filePath).Logger()

	rawData, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error().Err(err).Msg("failed to read file")
	}

	event := make(map[string]any)
	err = json.Unmarshal(rawData, &event)
	if err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal JSON")
	}

	return event
}
