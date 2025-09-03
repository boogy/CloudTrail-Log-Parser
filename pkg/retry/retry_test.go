package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDo(t *testing.T) {
	t.Run("successful operation", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		
		err := Do(ctx, func() error {
			callCount++
			return nil
		})
		
		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})
	
	t.Run("successful after retry", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		
		err := Do(ctx, func() error {
			callCount++
			if callCount < 3 {
				return errors.New("temporary error")
			}
			return nil
		}, WithMaxRetries(3))
		
		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})
	
	t.Run("max retries exceeded", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		
		err := Do(ctx, func() error {
			callCount++
			return errors.New("persistent error")
		}, WithMaxRetries(2))
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "operation failed after 2 retries")
		assert.Equal(t, 3, callCount) // Initial + 2 retries
	})
	
	t.Run("non-retryable error", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		nonRetryableErr := errors.New("non-retryable")
		
		err := Do(ctx, func() error {
			callCount++
			return nonRetryableErr
		}, WithRetryableError(func(err error) bool {
			return err != nonRetryableErr
		}))
		
		assert.Error(t, err)
		assert.Equal(t, nonRetryableErr, err)
		assert.Equal(t, 1, callCount) // No retries
	})
	
	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		callCount := 0
		
		// Cancel after first attempt
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		
		err := Do(ctx, func() error {
			callCount++
			return errors.New("error")
		}, WithBaseDelay(50*time.Millisecond))
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context cancelled")
		assert.Equal(t, 1, callCount) // Only first attempt
	})
	
	t.Run("with custom options", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		startTime := time.Now()
		
		err := Do(ctx, func() error {
			callCount++
			if callCount < 3 {
				return errors.New("retry me")
			}
			return nil
		}, 
			WithMaxRetries(5),
			WithBaseDelay(10*time.Millisecond),
			WithMaxDelay(100*time.Millisecond),
			WithMultiplier(2.0),
			WithJitter(false),
		)
		
		duration := time.Since(startTime)
		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
		// Should have delays of 10ms and 20ms (total 30ms minimum)
		assert.GreaterOrEqual(t, duration, 30*time.Millisecond)
	})
}

func TestDoTyped(t *testing.T) {
	t.Run("successful operation", func(t *testing.T) {
		ctx := context.Background()
		
		result, err := DoTyped(ctx, func() (string, error) {
			return "success", nil
		})
		
		assert.NoError(t, err)
		assert.Equal(t, "success", result)
	})
	
	t.Run("successful after retry", func(t *testing.T) {
		ctx := context.Background()
		callCount := 0
		
		result, err := DoTyped(ctx, func() (int, error) {
			callCount++
			if callCount < 3 {
				return 0, errors.New("temporary error")
			}
			return 42, nil
		}, WithMaxRetries(3))
		
		assert.NoError(t, err)
		assert.Equal(t, 42, result)
		assert.Equal(t, 3, callCount)
	})
	
	t.Run("error with zero value", func(t *testing.T) {
		ctx := context.Background()
		
		result, err := DoTyped(ctx, func() (int, error) {
			return 0, errors.New("failed")
		}, WithMaxRetries(0))
		
		assert.Error(t, err)
		assert.Equal(t, 0, result)
	})
}

func TestCalculateDelay(t *testing.T) {
	cfg := &Config{
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   1 * time.Second,
		Multiplier: 2.0,
		Jitter:     false,
	}
	
	t.Run("exponential growth", func(t *testing.T) {
		delay0 := calculateDelay(0, cfg)
		delay1 := calculateDelay(1, cfg)
		delay2 := calculateDelay(2, cfg)
		
		assert.Equal(t, 100*time.Millisecond, delay0)
		assert.Equal(t, 200*time.Millisecond, delay1)
		assert.Equal(t, 400*time.Millisecond, delay2)
	})
	
	t.Run("max delay cap", func(t *testing.T) {
		delay10 := calculateDelay(10, cfg)
		assert.Equal(t, 1*time.Second, delay10)
	})
	
	t.Run("with jitter", func(t *testing.T) {
		cfgWithJitter := &Config{
			BaseDelay:  100 * time.Millisecond,
			MaxDelay:   1 * time.Second,
			Multiplier: 2.0,
			Jitter:     true,
		}
		
		// Test multiple times to ensure jitter is applied
		delays := make([]time.Duration, 10)
		for i := 0; i < 10; i++ {
			delays[i] = calculateDelay(1, cfgWithJitter)
		}
		
		// With jitter, delays should vary
		allSame := true
		for i := 1; i < 10; i++ {
			if delays[i] != delays[0] {
				allSame = false
				break
			}
		}
		assert.False(t, allSame, "Jitter should produce varying delays")
		
		// All delays should be between 200ms and 250ms (base + up to 25% jitter)
		for _, delay := range delays {
			assert.GreaterOrEqual(t, delay, 200*time.Millisecond)
			assert.LessOrEqual(t, delay, 250*time.Millisecond)
		}
	})
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "timeout error",
			err:      errors.New("request timeout"),
			expected: true,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "throttling error",
			err:      errors.New("ThrottlingException: Rate exceeded"),
			expected: true,
		},
		{
			name:     "service unavailable",
			err:      errors.New("ServiceUnavailable"),
			expected: true,
		},
		{
			name:     "non-retryable error",
			err:      errors.New("invalid parameter"),
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.BaseDelay)
	assert.Equal(t, 10*time.Second, cfg.MaxDelay)
	assert.Equal(t, 2.0, cfg.Multiplier)
	assert.True(t, cfg.Jitter)
	assert.NotNil(t, cfg.RetryableError)
}

// Benchmark tests
func BenchmarkDo(b *testing.B) {
	ctx := context.Background()
	
	b.Run("no retries", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Do(ctx, func() error {
				return nil
			})
		}
	})
	
	b.Run("with retries", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			callCount := 0
			_ = Do(ctx, func() error {
				callCount++
				if callCount < 2 {
					return errors.New("retry")
				}
				return nil
			}, WithBaseDelay(1*time.Microsecond))
		}
	})
}