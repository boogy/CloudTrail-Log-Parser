package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds retry configuration
type Config struct {
	MaxRetries     int
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	Multiplier     float64
	Jitter         bool
	RetryableError func(error) bool
}

// DefaultConfig returns a default retry configuration
func DefaultConfig() *Config {
	return &Config{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   10 * time.Second,
		Multiplier: 2.0,
		Jitter:     true,
		RetryableError: func(err error) bool {
			return true // By default, retry all errors
		},
	}
}

// Option is a function that modifies Config
type Option func(*Config)

// WithMaxRetries sets the maximum number of retries
func WithMaxRetries(n int) Option {
	return func(c *Config) {
		c.MaxRetries = n
	}
}

// WithBaseDelay sets the base delay for exponential backoff
func WithBaseDelay(d time.Duration) Option {
	return func(c *Config) {
		c.BaseDelay = d
	}
}

// WithMaxDelay sets the maximum delay between retries
func WithMaxDelay(d time.Duration) Option {
	return func(c *Config) {
		c.MaxDelay = d
	}
}

// WithMultiplier sets the exponential backoff multiplier
func WithMultiplier(m float64) Option {
	return func(c *Config) {
		c.Multiplier = m
	}
}

// WithJitter enables or disables jitter
func WithJitter(enabled bool) Option {
	return func(c *Config) {
		c.Jitter = enabled
	}
}

// WithRetryableError sets a function to determine if an error is retryable
func WithRetryableError(f func(error) bool) Option {
	return func(c *Config) {
		c.RetryableError = f
	}
}

// Do executes a function with exponential backoff retry logic
func Do(ctx context.Context, fn func() error, opts ...Option) error {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	return DoWithConfig(ctx, fn, cfg)
}

// DoWithConfig executes a function with retry logic using the provided configuration
func DoWithConfig(ctx context.Context, fn func() error, cfg *Config) error {
	var lastErr error

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check context before attempting
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		err := fn()
		if err == nil {
			if attempt > 0 {
				log.Ctx(ctx).Debug().
					Int("attempt", attempt).
					Msg("operation succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !cfg.RetryableError(err) {
			log.Ctx(ctx).Debug().
				Err(err).
				Msg("non-retryable error, giving up")
			return err
		}

		// Don't sleep after the last attempt
		if attempt == cfg.MaxRetries {
			break
		}

		delay := calculateDelay(attempt, cfg)

		log.Ctx(ctx).Debug().
			Int("attempt", attempt).
			Err(err).
			Dur("delay", delay).
			Msg("operation failed, retrying")

		// Sleep with context cancellation support
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
	}

	return fmt.Errorf("operation failed after %d retries: %w", cfg.MaxRetries, lastErr)
}

// DoTyped executes a function that returns a value with retry logic
func DoTyped[T any](ctx context.Context, fn func() (T, error), opts ...Option) (T, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	var result T
	var lastErr error

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check context before attempting
		select {
		case <-ctx.Done():
			return result, fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		res, err := fn()
		if err == nil {
			if attempt > 0 {
				log.Ctx(ctx).Debug().
					Int("attempt", attempt).
					Msg("operation succeeded after retry")
			}
			return res, nil
		}

		lastErr = err

		// Check if error is retryable
		if !cfg.RetryableError(err) {
			log.Ctx(ctx).Debug().
				Err(err).
				Msg("non-retryable error, giving up")
			return result, err
		}

		// Don't sleep after the last attempt
		if attempt == cfg.MaxRetries {
			break
		}

		delay := calculateDelay(attempt, cfg)

		log.Ctx(ctx).Debug().
			Int("attempt", attempt).
			Err(err).
			Dur("delay", delay).
			Msg("operation failed, retrying")

		// Sleep with context cancellation support
		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			return result, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
	}

	return result, fmt.Errorf("operation failed after %d retries: %w", cfg.MaxRetries, lastErr)
}

// calculateDelay calculates the delay for the given attempt
func calculateDelay(attempt int, cfg *Config) time.Duration {
	// Calculate exponential backoff
	delay := float64(cfg.BaseDelay) * math.Pow(cfg.Multiplier, float64(attempt))

	// Apply jitter if enabled
	if cfg.Jitter {
		// Add random jitter between 0% and 25% of the delay
		jitter := rand.Float64() * 0.25 * delay
		delay = delay + jitter
	}

	// Cap at max delay
	if delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}

	return time.Duration(delay)
}

// IsRetryable checks if an error should be retried based on common patterns
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Add common retryable error patterns here
	// This is a simplified version - you may want to check for specific AWS errors
	errStr := err.Error()

	// Network and timeout errors
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"no such host",
		"temporary failure",
		"TooManyRequests",
		"RequestLimitExceeded",
		"ServiceUnavailable",
		"ThrottlingException",
		"ProvisionedThroughputExceededException",
		"TransactionInProgressException",
		"RequestThrottled",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr)) ||
			containsMiddle(s, substr))
}

func containsMiddle(s, substr string) bool {
	if len(s) <= len(substr) {
		return false
	}
	for i := 1; i < len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
