# CloudTrail Log Parser - API & Function Reference

## Table of Contents

1. [Package Overview](#package-overview)
2. [Core APIs](#core-apis)
3. [Configuration APIs](#configuration-apis)
4. [Processing APIs](#processing-apis)
5. [Rules Engine APIs](#rules-engine-apis)
6. [Metrics APIs](#metrics-apis)
7. [Utility Functions](#utility-functions)
8. [Type Definitions](#type-definitions)

## Package Overview

### Package Structure

```
ctlp/
├── cmd/                     # Application entry points
├── pkg/
│   ├── aws/                 # AWS service integration
│   ├── cloudtrailprocessor/ # Core processing logic
│   ├── config/              # Configuration management
│   ├── flags/               # CLI flags and configuration
│   ├── metrics/             # CloudWatch metrics
│   ├── processor/           # Streaming processor
│   ├── retry/               # Retry logic
│   ├── rules/               # Rule engine
│   ├── snsevents/           # SNS event handling
│   └── utils/               # Utility functions
```

## Core APIs

### Lambda Handler

#### `OptimizedHandler`

Main Lambda handler function with optimizations for cold starts and performance.

```go
func OptimizedHandler(ctx context.Context, event any) ([]byte, error)
```

**Parameters:**
- `ctx`: Context for cancellation and tracing
- `event`: Raw Lambda event (SNS, S3, or custom)

**Returns:**
- `[]byte`: Response payload
- `error`: Processing error if any

**Features:**
- Automatic configuration refresh
- Metrics collection
- Error retry with exponential backoff
- Memory usage tracking

**Example Usage:**
```go
lambda.StartWithOptions(OptimizedHandler, lambda.WithContext(context.Background()))
```

---

## Configuration APIs

### Package: `pkg/config`

#### `ConfigLoader` Interface

```go
type ConfigLoader interface {
    Load(ctx context.Context) (*rules.Configuration, error)
    String() string
}
```

Defines the contract for configuration loading from various sources.

#### `CreateLoaderFromEnv`

Creates a configuration loader based on environment variables.

```go
func CreateLoaderFromEnv(awsConfig *aws.Config) ConfigLoader
```

**Supported Sources:**
- `local`: Local file system
- `s3`: S3 bucket
- `ssm`: SSM Parameter Store
- `secretsmanager`: AWS Secrets Manager

**Environment Variables:**
- `CONFIG_SOURCE`: Source type
- `CONFIG_FILE`: Local file path
- `CONFIG_S3_BUCKET/KEY`: S3 location
- `CONFIG_SSM_PARAMETER`: SSM parameter name
- `CONFIG_SECRET_ID`: Secrets Manager ID

#### `S3ConfigLoader`

Loads configuration from S3.

```go
type S3ConfigLoader struct {
    bucket string
    key    string
    client S3API
}

func NewS3ConfigLoader(bucket, key string, client S3API) *S3ConfigLoader
func (l *S3ConfigLoader) Load(ctx context.Context) (*rules.Configuration, error)
```

#### `SSMConfigLoader`

Loads configuration from SSM Parameter Store.

```go
type SSMConfigLoader struct {
    parameterName string
    client        SSMAPI
}

func NewSSMConfigLoader(parameterName string, client SSMAPI) *SSMConfigLoader
func (l *SSMConfigLoader) Load(ctx context.Context) (*rules.Configuration, error)
```

#### `CachedConfigLoader`

Wraps any loader with caching capabilities.

```go
type CachedConfigLoader struct {
    loader      ConfigLoader
    ttl         time.Duration
    // ... internal fields
}

func NewCachedConfigLoader(loader ConfigLoader, ttl time.Duration) *CachedConfigLoader
func (l *CachedConfigLoader) Load(ctx context.Context) (*rules.Configuration, error)
func (l *CachedConfigLoader) LoadCached(ctx context.Context) (*rules.CachedConfiguration, error)
```

**Features:**
- TTL-based cache invalidation
- Thread-safe concurrent access
- Pre-compiled regex patterns

---

## Processing APIs

### Package: `pkg/cloudtrailprocessor`

#### `S3Copier`

Main processor for copying and filtering CloudTrail logs.

```go
type S3Copier struct {
    S3svc        S3API
    S3Downloader DownloaderAPI
    UploadSvc    UploaderAPI
    Cfg          flags.S3Processor
}
```

#### `NewCopier`

Creates a new S3Copier instance.

```go
func NewCopier(cfg flags.S3Processor, awscfg *aws.Config) *S3Copier
```

#### `Copy`

Copies and filters a CloudTrail log file.

```go
func (cp *S3Copier) Copy(ctx context.Context, bucket, key string) error
```

**Process:**
1. Downloads file from source bucket
2. Decompresses if needed
3. Applies filtering rules
4. Compresses filtered output
5. Uploads to destination bucket

#### `CopyWithCachedRules`

Optimized version using pre-compiled rules.

```go
func (cp *S3Copier) CopyWithCachedRules(
    ctx context.Context,
    bucket, key string,
    cachedRules *rules.CachedConfiguration
) error
```

#### `DownloadCloudtrail`

Downloads and decompresses a CloudTrail file.

```go
func (cp *S3Copier) DownloadCloudtrail(
    ctx context.Context,
    bucket, key string
) (*Cloudtrail, error)
```

#### `DownloadCloudtrailMultiPart`

Downloads large files using multipart download.

```go
func (cp *S3Copier) DownloadCloudtrailMultiPart(
    ctx context.Context,
    bucket, key string
) (*Cloudtrail, error)
```

**Features:**
- Automatic decompression
- Memory-efficient streaming
- Size limits (500MB max)

#### `FilterRecords`

Filters CloudTrail records based on rules.

```go
func FilterRecords(
    ctx context.Context,
    inct *Cloudtrail,
    cachedCfg *rules.CachedConfiguration
) (*Cloudtrail, error)
```

**Algorithm:**
1. Processes records in batches
2. Evaluates rules for each record
3. Filters out matching records
4. Returns filtered CloudTrail object

### Package: `pkg/processor`

#### `StreamingProcessor`

Memory-efficient streaming JSON processor.

```go
type StreamingProcessor struct {
    rules      *rules.CachedConfiguration
    metrics    MetricsCollector
    bufferPool *sync.Pool
    writerPool *sync.Pool
}
```

#### `NewStreamingProcessor`

Creates a new streaming processor.

```go
func NewStreamingProcessor(
    rules *rules.CachedConfiguration,
    metrics MetricsCollector
) *StreamingProcessor
```

#### `ProcessStream`

Processes CloudTrail records in streaming fashion.

```go
func (sp *StreamingProcessor) ProcessStream(
    ctx context.Context,
    input io.Reader,
    output io.Writer,
    compressed bool
) (*ProcessingResult, error)
```

**Features:**
- Constant memory usage
- Line-by-line processing
- Optional compression
- Progress tracking

#### `ProcessBatch`

Processes CloudTrail records in batch mode.

```go
func (sp *StreamingProcessor) ProcessBatch(
    ctx context.Context,
    input *Cloudtrail
) (*Cloudtrail, *ProcessingResult, error)
```

**Features:**
- Parallel processing
- Better for smaller files
- Detailed metrics

---

## Rules Engine APIs

### Package: `pkg/rules`

#### `Configuration`

Basic rule configuration structure.

```go
type Configuration struct {
    Rules []*Rule `yaml:"rules" validate:"required,dive"`
}
```

#### `Rule`

Individual filtering rule.

```go
type Rule struct {
    Name    string   `yaml:"name" validate:"required"`
    Matches []*Match `yaml:"matches" validate:"required,dive"`
}
```

#### `Match`

Field matching condition.

```go
type Match struct {
    FieldName string `yaml:"field_name" validate:"required"`
    Regex     string `yaml:"regex" validate:"is-regex"`
}
```

#### `Load`

Loads configuration from string.

```go
func Load(rawCfg string) (*Configuration, error)
```

#### `LoadFromConfigFile`

Loads configuration from file.

```go
func LoadFromConfigFile(ctx context.Context, path string) (*Configuration, error)
```

#### `EvalRules`

Evaluates all rules against an event.

```go
func (cr *Configuration) EvalRules(evt map[string]any) (bool, *DropedEvent, error)
```

**Returns:**
- `bool`: True if event should be filtered
- `*DropedEvent`: Details about the matched rule
- `error`: Evaluation error if any

#### `Validate`

Validates configuration structure and patterns.

```go
func (cr *Configuration) Validate() error
```

**Validates:**
- Required fields
- Regex compilation
- ReDoS patterns
- Field paths

### Versioned Configuration

#### `VersionedConfiguration`

Extended configuration with versioning and metadata.

```go
type VersionedConfiguration struct {
    Version string      `yaml:"version" validate:"required,semver"`
    Rules   []*Rule     `yaml:"rules" validate:"required,dive"`
    Meta    *ConfigMeta `yaml:"meta,omitempty"`
}
```

#### `LoadVersioned`

Loads versioned configuration.

```go
func LoadVersioned(rawCfg string) (*VersionedConfiguration, error)
```

#### `DryRun`

Tests configuration against sample events.

```go
func (vc *VersionedConfiguration) DryRun(
    sampleEvents []map[string]any
) (*DryRunResult, error)
```

#### `Export`

Exports configuration in different formats.

```go
func (vc *VersionedConfiguration) Export(format string) ([]byte, error)
```

**Supported Formats:**
- `yaml`: YAML format
- `json`: JSON format

### Cached Configuration

#### `CachedConfiguration`

Optimized configuration with pre-compiled patterns.

```go
type CachedConfiguration struct {
    Rules []*CachedRule
}
```

#### `PrepareConfiguration`

Creates cached configuration from regular configuration.

```go
func PrepareConfiguration(cfg *Configuration) (*CachedConfiguration, error)
```

**Optimizations:**
- Pre-compiles regex patterns
- Caches compiled patterns
- Improves evaluation speed by 10x

---

## Metrics APIs

### Package: `pkg/metrics`

#### `CloudWatchMetrics`

CloudWatch metrics collector.

```go
type CloudWatchMetrics struct {
    client    *cloudwatch.Client
    namespace string
    // ... internal fields
}
```

#### `NewCloudWatchMetrics`

Creates new metrics collector.

```go
func NewCloudWatchMetrics(
    client *cloudwatch.Client,
    namespace string
) *CloudWatchMetrics
```

#### Metric Recording Functions

```go
// Record processing time
func (cwm *CloudWatchMetrics) RecordProcessingTime(
    duration time.Duration,
    dimensions map[string]string
)

// Record number of records processed
func (cwm *CloudWatchMetrics) RecordRecordsProcessed(
    count int,
    dimensions map[string]string
)

// Record number of records filtered
func (cwm *CloudWatchMetrics) RecordRecordsFiltered(
    count int,
    dimensions map[string]string
)

// Record filter rate percentage
func (cwm *CloudWatchMetrics) RecordFilterRate(
    rate float64,
    dimensions map[string]string
)

// Record error occurrence
func (cwm *CloudWatchMetrics) RecordError(
    errorType string,
    dimensions map[string]string
)

// Record Lambda execution duration
func (cwm *CloudWatchMetrics) RecordLambdaDuration(
    duration time.Duration,
    dimensions map[string]string
)

// Record memory usage
func (cwm *CloudWatchMetrics) RecordMemoryUsed(
    memoryMB float64,
    dimensions map[string]string
)

// Record configuration load time
func (cwm *CloudWatchMetrics) RecordConfigLoadTime(
    duration time.Duration,
    source string,
    dimensions map[string]string
)

// Record S3 operations
func (cwm *CloudWatchMetrics) RecordS3Operations(
    operation string,
    duration time.Duration,
    success bool,
    dimensions map[string]string
)
```

#### `Flush`

Sends buffered metrics to CloudWatch.

```go
func (cwm *CloudWatchMetrics) Flush(ctx context.Context) error
```

---

## Utility Functions

### Package: `pkg/utils`

#### Field Operations

```go
// Check if field exists in event
func FieldExists(field string, event map[string]any) (bool, any)

// Extract string field from event
func ExtractStringField(evt map[string]any, key string) string
```

#### JSON Operations

```go
// Marshal to JSON
func Marshal(v any) ([]byte, error)

// Unmarshal from JSON
func Unmarshal(payload []byte, v any) bool
```

#### File Operations

```go
// Read file contents safely
func ReadFileContents(filepath string) (string, error)
```

### Package: `pkg/retry`

#### Retry Configuration

```go
type Config struct {
    MaxRetries     int
    BaseDelay      time.Duration
    MaxDelay       time.Duration
    Multiplier     float64
    Jitter         bool
    RetryableError func(error) bool
}
```

#### `Do`

Execute function with retry logic.

```go
func Do(ctx context.Context, fn func() error, opts ...Option) error
```

#### `DoTyped`

Execute typed function with retry logic.

```go
func DoTyped[T any](
    ctx context.Context,
    fn func() (T, error),
    opts ...Option
) (T, error)
```

#### Options

```go
// Set maximum retries
func WithMaxRetries(max int) Option

// Set base delay
func WithBaseDelay(delay time.Duration) Option

// Set retryable error checker
func WithRetryableError(checker func(error) bool) Option
```

---

## Type Definitions

### CloudTrail Types

```go
// CloudTrail document structure
type Cloudtrail struct {
    Records []json.RawMessage `json:"Records"`
}

// SNS event from CloudTrail
type CloudtrailSNSEvent struct {
    S3Bucket     string   `json:"s3Bucket,omitempty"`
    S3ObjectKeys []string `json:"s3ObjectKey,omitempty"`
}
```

### Processing Types

```go
// Processing result metrics
type ProcessingResult struct {
    ProcessedCount int
    FilteredCount  int
    OutputSize     int64
}

// Dropped event information
type DropedEvent struct {
    RuleName string `json:"rule_name"`
}

// Dry run results
type DryRunResult struct {
    TotalEvents   int
    FilteredCount int
    PassedCount   int
    FilterRate    float64
    RuleHits      map[string]int
}
```

### Configuration Types

```go
// S3 processor configuration
type S3Processor struct {
    CloudtrailOutputBucketName string
    SNSPayloadType            string
    SNSTopicArn               string
    SQSQueueURL               string
    MultiPartDownload         bool
    ConfigFile                string
}

// Configuration metadata
type ConfigMeta struct {
    Description string            `yaml:"description,omitempty"`
    Author      string            `yaml:"author,omitempty"`
    CreatedAt   string            `yaml:"created_at,omitempty"`
    UpdatedAt   string            `yaml:"updated_at,omitempty"`
    Tags        []string          `yaml:"tags,omitempty"`
    Labels      map[string]string `yaml:"labels,omitempty"`
}
```

### Interface Definitions

```go
// S3 operations interface
type S3API interface {
    GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3 downloader interface
type DownloaderAPI interface {
    Download(context.Context, io.WriterAt, *s3.GetObjectInput, ...func(*manager.Downloader)) (int64, error)
}

// S3 uploader interface
type UploaderAPI interface {
    Upload(context.Context, *s3.PutObjectInput, ...func(*manager.Uploader)) (*manager.UploadOutput, error)
}

// Metrics collector interface
type MetricsCollector interface {
    RecordProcessed(count int)
    RecordFiltered(count int)
    RecordError(err error)
}

// CloudTrail copier interface
type Copier interface {
    Copy(ctx context.Context, bucket, key string) error
}
```

## Error Handling

### Common Error Types

```go
// Configuration validation error
type ValidationError struct {
    Field   string
    Rule    string
    Message string
}

// Collection of validation errors
type ValidationErrors []ValidationError
```

### Error Checking Functions

```go
// Check if error is retryable
func IsRetryable(err error) bool
```

**Retryable Patterns:**
- Network timeouts
- Connection refused
- Rate limiting (TooManyRequests)
- Service unavailable (503)
- Request timeout (408)
- Throttling exceptions

## Best Practices

### Configuration Loading

```go
// Use cached loader for production
loader := config.CreateLoaderFromEnv(&awsConfig)
cachedLoader := config.NewCachedConfigLoader(loader, 5*time.Minute)

// Load configuration with retry
cfg, err := retry.DoTyped(ctx, func() (*rules.Configuration, error) {
    return cachedLoader.Load(ctx)
}, retry.WithMaxRetries(3))
```

### Rule Evaluation

```go
// Prepare rules once for better performance
cachedRules, err := rules.PrepareConfiguration(cfg)
if err != nil {
    return err
}

// Reuse cached rules for multiple evaluations
for _, event := range events {
    match, dropEvent, err := cachedRules.EvalRules(event)
    if match {
        log.Info().Str("rule", dropEvent.RuleName).Msg("event filtered")
    }
}
```

### Metrics Collection

```go
// Initialize metrics collector
cwMetrics := metrics.NewCloudWatchMetrics(cwClient, "CloudTrailFilter")

// Record metrics with dimensions
dimensions := map[string]string{
    "Environment": "production",
    "Region":      "us-east-1",
}

cwMetrics.RecordProcessingTime(duration, dimensions)
cwMetrics.RecordRecordsProcessed(1000, dimensions)
cwMetrics.RecordFilterRate(0.75, dimensions)

// Flush metrics before Lambda completion
defer cwMetrics.Flush(ctx)
```

### Error Handling with Retry

```go
// Configure retry with exponential backoff
err := retry.Do(ctx, func() error {
    return processor.Copy(ctx, bucket, key)
},
    retry.WithMaxRetries(3),
    retry.WithBaseDelay(100*time.Millisecond),
    retry.WithRetryableError(retry.IsRetryable),
)

if err != nil {
    log.Error().Err(err).Msg("processing failed after retries")
    return err
}
```

## Performance Considerations

### Memory Optimization

- Use object pools for frequent allocations
- Stream large files instead of loading into memory
- Clear maps before returning to pool
- Use buffered I/O for file operations

### CPU Optimization

- Pre-compile regex patterns
- Use batch processing for cache locality
- Early exit on rule matches
- Parallel processing for large batches

### Network Optimization

- Use multipart download for large files
- Enable connection keep-alive
- Configure regional endpoints
- Implement retry with backoff

### Cold Start Optimization

- Initialize globals in init()
- Use lazy loading for heavy resources
- Pre-warm configuration cache
- Pool AWS service clients
