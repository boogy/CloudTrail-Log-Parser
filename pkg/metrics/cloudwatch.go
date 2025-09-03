package metrics

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/rs/zerolog/log"
)

// CloudWatchMetrics collects and publishes metrics to CloudWatch
type CloudWatchMetrics struct {
	client    *cloudwatch.Client
	namespace string

	// Buffering for batch publishing
	mu      sync.Mutex
	metrics []types.MetricDatum

	// Configuration
	batchSize     int
	flushInterval time.Duration
	enabled       bool

	// Background flushing
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewCloudWatchMetrics creates a new CloudWatch metrics collector
func NewCloudWatchMetrics(client *cloudwatch.Client, namespace string) *CloudWatchMetrics {
	enabled := os.Getenv("METRICS_ENABLED") != "false" // Default to enabled

	cwm := &CloudWatchMetrics{
		client:        client,
		namespace:     namespace,
		metrics:       make([]types.MetricDatum, 0, 20),
		batchSize:     20, // CloudWatch max is 20 metrics per request
		flushInterval: 10 * time.Second,
		enabled:       enabled,
		stopCh:        make(chan struct{}),
	}

	if enabled {
		cwm.startBackgroundFlusher()
	}

	return cwm
}

// startBackgroundFlusher starts a goroutine that periodically flushes metrics
func (cwm *CloudWatchMetrics) startBackgroundFlusher() {
	cwm.wg.Add(1)
	go func() {
		defer cwm.wg.Done()
		ticker := time.NewTicker(cwm.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := cwm.Flush(context.Background()); err != nil {
					log.Error().Err(err).Msg("failed to flush metrics")
				}
			case <-cwm.stopCh:
				return
			}
		}
	}()
}

// Stop stops the background flusher and flushes remaining metrics
func (cwm *CloudWatchMetrics) Stop(ctx context.Context) error {
	if !cwm.enabled {
		return nil
	}

	close(cwm.stopCh)
	cwm.wg.Wait()

	// Final flush
	return cwm.Flush(ctx)
}

// RecordProcessingTime records the time taken to process a file
func (cwm *CloudWatchMetrics) RecordProcessingTime(duration time.Duration, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("ProcessingTime"),
		Value:      aws.Float64(duration.Seconds()),
		Unit:       types.StandardUnitSeconds,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordRecordsProcessed records the number of records processed
func (cwm *CloudWatchMetrics) RecordRecordsProcessed(count int, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("RecordsProcessed"),
		Value:      aws.Float64(float64(count)),
		Unit:       types.StandardUnitCount,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordRecordsFiltered records the number of records filtered
func (cwm *CloudWatchMetrics) RecordRecordsFiltered(count int, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("RecordsFiltered"),
		Value:      aws.Float64(float64(count)),
		Unit:       types.StandardUnitCount,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordFilterRate records the percentage of records filtered
func (cwm *CloudWatchMetrics) RecordFilterRate(rate float64, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("FilterRate"),
		Value:      aws.Float64(rate * 100), // Convert to percentage
		Unit:       types.StandardUnitPercent,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordError records an error occurrence
func (cwm *CloudWatchMetrics) RecordError(errorType string, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	dims := cwm.buildDimensions(dimensions)
	dims = append(dims, types.Dimension{
		Name:  aws.String("ErrorType"),
		Value: aws.String(errorType),
	})

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("Errors"),
		Value:      aws.Float64(1),
		Unit:       types.StandardUnitCount,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: dims,
	})
}

// RecordFileSize records the size of processed files
func (cwm *CloudWatchMetrics) RecordFileSize(sizeBytes int64, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("FileSize"),
		Value:      aws.Float64(float64(sizeBytes)),
		Unit:       types.StandardUnitBytes,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordLambdaDuration records Lambda execution duration
func (cwm *CloudWatchMetrics) RecordLambdaDuration(duration time.Duration, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("LambdaDuration"),
		Value:      aws.Float64(float64(duration.Milliseconds())),
		Unit:       types.StandardUnitMilliseconds,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordMemoryUsed records memory usage
func (cwm *CloudWatchMetrics) RecordMemoryUsed(memoryMB float64, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("MemoryUsed"),
		Value:      aws.Float64(memoryMB),
		Unit:       types.StandardUnitMegabytes,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: cwm.buildDimensions(dimensions),
	})
}

// RecordConfigLoadTime records configuration loading time
func (cwm *CloudWatchMetrics) RecordConfigLoadTime(duration time.Duration, source string, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	dims := cwm.buildDimensions(dimensions)
	dims = append(dims, types.Dimension{
		Name:  aws.String("ConfigSource"),
		Value: aws.String(source),
	})

	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("ConfigLoadTime"),
		Value:      aws.Float64(float64(duration.Milliseconds())),
		Unit:       types.StandardUnitMilliseconds,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: dims,
	})
}

// RecordS3Operations records S3 operation metrics
func (cwm *CloudWatchMetrics) RecordS3Operations(operation string, duration time.Duration, success bool, dimensions map[string]string) {
	if !cwm.enabled {
		return
	}

	dims := cwm.buildDimensions(dimensions)
	dims = append(dims, types.Dimension{
		Name:  aws.String("Operation"),
		Value: aws.String(operation),
	})

	// Record duration
	cwm.addMetric(types.MetricDatum{
		MetricName: aws.String("S3OperationDuration"),
		Value:      aws.Float64(float64(duration.Milliseconds())),
		Unit:       types.StandardUnitMilliseconds,
		Timestamp:  aws.Time(time.Now()),
		Dimensions: dims,
	})

	// Record success/failure
	if !success {
		cwm.addMetric(types.MetricDatum{
			MetricName: aws.String("S3OperationErrors"),
			Value:      aws.Float64(1),
			Unit:       types.StandardUnitCount,
			Timestamp:  aws.Time(time.Now()),
			Dimensions: dims,
		})
	}
}

// buildDimensions builds CloudWatch dimensions from a map
func (cwm *CloudWatchMetrics) buildDimensions(dimensions map[string]string) []types.Dimension {
	dims := make([]types.Dimension, 0, len(dimensions)+1)

	// Add default dimensions
	if region := os.Getenv("AWS_REGION"); region != "" {
		dims = append(dims, types.Dimension{
			Name:  aws.String("Region"),
			Value: aws.String(region),
		})
	}

	// Add custom dimensions
	for name, value := range dimensions {
		dims = append(dims, types.Dimension{
			Name:  aws.String(name),
			Value: aws.String(value),
		})
	}

	return dims
}

// addMetric adds a metric to the buffer and flushes if necessary
func (cwm *CloudWatchMetrics) addMetric(metric types.MetricDatum) {
	cwm.mu.Lock()
	defer cwm.mu.Unlock()

	cwm.metrics = append(cwm.metrics, metric)

	// Auto-flush if batch size reached
	if len(cwm.metrics) >= cwm.batchSize {
		go func() {
			if err := cwm.Flush(context.Background()); err != nil {
				log.Error().Err(err).Msg("failed to auto-flush metrics")
			}
		}()
	}
}

// Flush sends all buffered metrics to CloudWatch
func (cwm *CloudWatchMetrics) Flush(ctx context.Context) error {
	if !cwm.enabled {
		return nil
	}

	cwm.mu.Lock()
	if len(cwm.metrics) == 0 {
		cwm.mu.Unlock()
		return nil
	}

	// Copy metrics and clear buffer
	metricsToSend := make([]types.MetricDatum, len(cwm.metrics))
	copy(metricsToSend, cwm.metrics)
	cwm.metrics = cwm.metrics[:0]
	cwm.mu.Unlock()

	// Send metrics in batches
	for i := 0; i < len(metricsToSend); i += cwm.batchSize {
		end := i + cwm.batchSize
		if end > len(metricsToSend) {
			end = len(metricsToSend)
		}

		batch := metricsToSend[i:end]

		_, err := cwm.client.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
			Namespace:  aws.String(cwm.namespace),
			MetricData: batch,
		})

		if err != nil {
			return fmt.Errorf("failed to put metric data: %w", err)
		}
	}

	log.Debug().Int("count", len(metricsToSend)).Msg("flushed metrics to CloudWatch")

	return nil
}

// SimpleMetricsCollector implements the processor.MetricsCollector interface
type SimpleMetricsCollector struct {
	cwm        *CloudWatchMetrics
	dimensions map[string]string
}

// NewSimpleMetricsCollector creates a metrics collector for the processor
func NewSimpleMetricsCollector(cwm *CloudWatchMetrics, dimensions map[string]string) *SimpleMetricsCollector {
	return &SimpleMetricsCollector{
		cwm:        cwm,
		dimensions: dimensions,
	}
}

// RecordProcessed records processed records
func (s *SimpleMetricsCollector) RecordProcessed(count int) {
	s.cwm.RecordRecordsProcessed(count, s.dimensions)
}

// RecordFiltered records filtered records
func (s *SimpleMetricsCollector) RecordFiltered(count int) {
	s.cwm.RecordRecordsFiltered(count, s.dimensions)
}

// RecordError records an error
func (s *SimpleMetricsCollector) RecordError(err error) {
	errorType := "Unknown"
	if err != nil {
		errorType = fmt.Sprintf("%T", err)
	}
	s.cwm.RecordError(errorType, s.dimensions)
}
