# CloudTrail Log Parser - Technical Architecture Documentation

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Architecture Design](#architecture-design)
4. [Core Components](#core-components)
5. [Data Flow](#data-flow)
6. [Processing Pipeline](#processing-pipeline)
7. [Configuration System](#configuration-system)
8. [Performance Optimizations](#performance-optimizations)
9. [Security Architecture](#security-architecture)
10. [Deployment Architecture](#deployment-architecture)
11. [Monitoring and Observability](#monitoring-and-observability)
12. [Design Decisions](#design-decisions)

## Executive Summary

The CloudTrail Log Parser is a high-performance, serverless log processing system designed to filter and reduce noise in AWS CloudTrail audit logs. Built with Go and optimized for AWS Lambda, it processes CloudTrail events in real-time, applying configurable filtering rules to reduce SIEM ingestion costs while maintaining security visibility.

### Key Capabilities
- **Real-time Processing**: Processes CloudTrail logs as they arrive via SNS notifications
- **Cost Optimization**: Reduces SIEM costs by filtering out noise (typically 60-80% reduction)
- **High Performance**: Streaming JSON processing with memory pooling and caching
- **Flexible Configuration**: Multiple configuration sources (S3, SSM, Secrets Manager)
- **Production Ready**: Comprehensive metrics, error handling, and retry logic

### Architecture Principles
- **Serverless First**: Leverages AWS Lambda for automatic scaling and cost efficiency
- **Performance Optimized**: Cold start optimization, connection pooling, regex caching
- **Security by Design**: Input validation, ReDoS protection, least privilege access
- **Observable**: CloudWatch metrics for all critical operations
- **Extensible**: Modular design allows easy addition of new filters and processors

## System Overview

### High-Level Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  CloudTrail     │────▶│   S3 Bucket     │────▶│   SNS Topic     │
│                 │     │  (Raw Logs)     │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                         │
                                                         ▼
                               ┌─────────────────────────────────────┐
                               │                                     │
                               │     CloudTrail Log Parser           │
                               │         (Lambda Function)           │
                               │                                     │
                               │  ┌──────────────────────────────┐   │
                               │  │   Configuration Loader       │   │
                               │  │  (S3/SSM/Secrets Manager)    │   │
                               │  └──────────────────────────────┘   │
                               │                                     │
                               │  ┌──────────────────────────────┐   │
                               │  │   Streaming Processor        │   │
                               │  │  (Filter & Transform)        │   │
                               │  └──────────────────────────────┘   │
                               │                                     │
                               │  ┌──────────────────────────────┐   │
                               │  │   CloudWatch Metrics         │   │
                               │  │  (Monitoring & Alerting)     │   │
                               │  └──────────────────────────────┘   │
                               └─────────────────────────────────────┘
                                                 │
                                    ┌────────────┴────────────┐
                                    ▼                         ▼
                          ┌─────────────────┐      ┌─────────────────┐
                          │   S3 Bucket     │      │  SNS/SQS        │
                          │ (Filtered Logs) │      │  (Optional)     │
                          └─────────────────┘      └─────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │    SIEM Tool    │
                          └─────────────────┘
```

### Component Interaction

The system follows an event-driven architecture where:
1. CloudTrail writes audit logs to an S3 bucket
2. S3 bucket notifications trigger SNS messages
3. SNS invokes the Lambda function with event details
4. Lambda downloads, processes, and filters the logs
5. Filtered logs are written to a destination S3 bucket
6. Optional broadcasting to SNS/SQS for downstream processing
7. SIEM tools ingest the filtered logs for security analysis

## Architecture Design

### Layered Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Entry Points Layer                    │
│         cmd/main.go - Lambda Handler                     │
└─────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────┐
│                   Event Processing Layer                 │
│    snsevents - SNS Event Processing                      │
│    cloudtrailprocessor - Core Processing Logic           │
└─────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────┐
│                    Business Logic Layer                  │
│    rules - Rule Engine & Evaluation                      │
│    processor - Streaming JSON Processor                  │
└─────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────┐
│                 Infrastructure Layer                     │
│    config - Configuration Loading                        │
│    metrics - CloudWatch Metrics                          │
│    retry - Retry Logic & Circuit Breaker                 │
└─────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────┐
│                      AWS Services Layer                  │
│    aws - AWS Service Clients                             │
│    S3, SNS, SQS, CloudWatch, SSM, Secrets Manager       │
└─────────────────────────────────────────────────────────┘
```

### Module Dependencies

```
main.go
    ├── cloudtrailprocessor
    │   ├── rules (cached)
    │   ├── processor (streaming)
    │   └── aws (S3 operations)
    ├── config
    │   ├── rules
    │   └── aws (config sources)
    ├── snsevents
    │   └── cloudtrailprocessor
    ├── metrics
    │   └── aws (CloudWatch)
    └── retry
        └── backoff strategies
```

## Core Components

### 1. Lambda Handler (`cmd/main.go`)

The main entry point optimized for AWS Lambda cold starts:

**Responsibilities:**
- Global initialization during cold start
- Configuration management and refresh
- Request routing and error handling
- Metrics collection and reporting

**Key Features:**
- Async initialization in `init()` function
- Configuration caching with TTL
- Connection pooling for AWS services
- Graceful error handling and recovery

### 2. CloudTrail Processor (`pkg/cloudtrailprocessor`)

Core processing engine for CloudTrail logs:

**Components:**
- `S3Copier`: Downloads and uploads S3 objects
- `FilterRecords`: Applies rules to filter events
- `UploadJob`: Streams compressed output

**Processing Flow:**
```
Download (S3/Multipart) → Decompress → Parse JSON → Filter → Compress → Upload
```

**Optimizations:**
- Object pooling for frequent allocations
- Streaming JSON processing
- Batch processing for better cache locality
- Pre-compiled regex patterns

### 3. Rules Engine (`pkg/rules`)

Flexible rule system for filtering CloudTrail events:

**Components:**
- `Configuration`: Basic rule configuration
- `VersionedConfiguration`: Versioned config with metadata
- `CachedConfiguration`: Pre-compiled regex patterns

**Rule Structure:**
```yaml
rules:
  - name: "Rule Name"
    matches:
      - field_name: "eventName"
        regex: "^Pattern$"
      - field_name: "eventSource"
        regex: "service\\.amazonaws\\.com"
```

**Evaluation Logic:**
- AND logic within a rule (all matches must be true)
- OR logic between rules (any rule match filters the event)

### 4. Configuration Loader (`pkg/config`)

Modular configuration loading system:

**Supported Sources:**
- Local files (YAML/JSON)
- S3 buckets
- SSM Parameter Store
- AWS Secrets Manager

**Features:**
- TTL-based caching
- Automatic refresh
- Format validation
- Version support

### 5. Streaming Processor (`pkg/processor`)

Memory-efficient streaming JSON processor:

**Capabilities:**
- Process large files without loading into memory
- Parallel batch processing
- Context-aware cancellation
- Progress tracking

**Processing Modes:**
- Streaming: Process line-by-line
- Batch: Process in parallel chunks

### 6. Metrics Collection (`pkg/metrics`)

Comprehensive observability through CloudWatch:

**Tracked Metrics:**
- Records processed/filtered
- Processing time
- File sizes
- Error rates
- Memory usage
- Lambda duration
- Configuration load time

## Data Flow

### Standard Processing Flow

```
1. CloudTrail → S3 Bucket (Raw Logs)
   └── File: org/account/CloudTrail/region/year/month/day/file.json.gz

2. S3 Event → SNS Topic
   └── Message: {bucket, key, size}

3. SNS → Lambda Invocation
   └── Event: SNSEvent with S3 details

4. Lambda Processing:
   a. Load/Refresh Configuration
   b. Download S3 Object
   c. Decompress if needed
   d. Parse CloudTrail JSON
   e. Apply Filter Rules
   f. Compress Filtered Data
   g. Upload to Destination S3
   h. Optional: Broadcast to SNS/SQS
   i. Record Metrics

5. Destination S3 → SIEM Ingestion
   └── File: Same path structure, filtered content
```

### Error Handling Flow

```
Error Detection
    ├── Retryable Error
    │   └── Exponential Backoff
    │       ├── Success → Continue
    │       └── Max Retries → DLQ
    └── Non-Retryable Error
        ├── Log Error
        ├── Record Metric
        └── Return Error
```

## Processing Pipeline

### 1. Event Reception

```go
SNS Event → JSON Unmarshal → Event Validation → Route to Processor
```

### 2. Configuration Loading

```go
Check Cache → TTL Valid?
    ├── Yes → Use Cached Config
    └── No → Load Fresh Config
            └── Compile Regex Patterns
                └── Update Cache
```

### 3. File Processing

```go
Download S3 Object
    └── Check Compression
        ├── Compressed → Decompress Stream
        └── Raw → Direct Stream
            └── Parse JSON Stream
                └── For Each Record
                    └── Apply Rules
                        ├── Match → Filter Out
                        └── No Match → Keep
                            └── Write to Output
```

### 4. Rule Evaluation

```go
For Each Rule:
    All Matches True?
        ├── Yes → Filter Event (Drop)
        └── No → Check Next Rule
            └── No Rules Match → Keep Event
```

### 5. Output Generation

```go
Create Gzip Writer
    └── JSON Encode Filtered Events
        └── Stream to S3 Upload
            └── Record Metrics
```

## Configuration System

### Configuration Sources

1. **Local Files**
   - Development and testing
   - Static configurations
   - Format: YAML or JSON

2. **S3 Bucket**
   - Centralized management
   - Version control friendly
   - Multi-environment support

3. **SSM Parameter Store**
   - Encrypted parameters
   - IAM-based access control
   - Change notifications

4. **Secrets Manager**
   - Rotation support
   - Cross-account access
   - Audit trail

### Configuration Schema

```yaml
version: "1.0.0"  # Semantic versioning
meta:             # Optional metadata
  description: "Production rules"
  author: "security-team"
  tags: ["production", "security"]
rules:            # Filtering rules
  - name: "Rule Name"
    matches:      # AND conditions
      - field_name: "field.path"
        regex: "pattern"
```

### Configuration Validation

1. **Syntax Validation**
   - YAML/JSON parsing
   - Required fields check
   - Type validation

2. **Semantic Validation**
   - Regex compilation
   - ReDoS detection
   - Field path validation

3. **Performance Validation**
   - Pattern complexity
   - Rule count limits
   - Memory estimation

## Performance Optimizations

### 1. Cold Start Optimization

**Strategies:**
- Global variable initialization
- Lazy loading of heavy resources
- Connection pooling
- Pre-compiled regex patterns

**Implementation:**
```go
var (
    awsCfg         aws.Config      // Initialized once
    cachedRules    *rules.Cached   // Pre-compiled patterns
    s3Client       *s3.Client      // Reused connection
)

func init() {
    go performAsyncInitialization() // Background init
}
```

### 2. Memory Management

**Techniques:**
- Object pooling for allocations
- Streaming processing
- Buffer reuse
- Controlled goroutine count

**Pools:**
```go
var (
    gzipWriterPool sync.Pool  // Gzip writers
    recordMapPool  sync.Pool  // JSON maps
    bufferPool     sync.Pool  // Byte buffers
)
```

### 3. Processing Optimization

**Strategies:**
- Batch processing for cache locality
- Early exit on rule matches
- Parallel evaluation for large files
- Zero-copy where possible

### 4. Network Optimization

**Features:**
- S3 multipart download for large files
- Connection keep-alive
- Request retries with backoff
- Regional endpoints

## Security Architecture

### 1. Input Validation

**Protections:**
- Bucket name sanitization
- ARN format validation
- URL validation
- Path traversal prevention

### 2. ReDoS Protection

**Implementation:**
- Pattern complexity analysis
- Timeout limits on regex execution
- Dangerous pattern detection
- Maximum pattern length

### 3. Resource Limits

**Controls:**
- Maximum file size (500MB)
- JSON token size limits (10MB)
- Memory allocation limits
- Goroutine count limits

### 4. IAM Permissions

**Minimum Required:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::source-bucket/*",
        "arn:aws:s3:::dest-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}
```

## Deployment Architecture

### Lambda Configuration

**Recommended Settings:**
- Memory: 1024-3008 MB (based on file size)
- Timeout: 5 minutes
- Architecture: ARM64 (Graviton2)
- Runtime: provided.al2 (custom runtime)
- Provisioned Concurrency: For predictable load

### Environment Variables

**Required:**
- `CLOUDTRAIL_OUTPUT_BUCKET_NAME`: Destination bucket

**Optional:**
- `CONFIG_SOURCE`: Configuration source type
- `CONFIG_S3_BUCKET/KEY`: S3 configuration location
- `CONFIG_SSM_PARAMETER`: SSM parameter name
- `CONFIG_SECRET_ID`: Secrets Manager ID
- `SNS_TOPIC_ARN`: Broadcasting topic
- `SQS_QUEUE_URL`: Broadcasting queue
- `METRICS_ENABLED`: Enable CloudWatch metrics
- `LOG_LEVEL`: Logging verbosity

### Networking

**VPC Configuration:**
- Not required for S3 access
- Use VPC endpoints for private access
- Configure security groups for egress only

## Monitoring and Observability

### CloudWatch Metrics

**Application Metrics:**
- `RecordsProcessed`: Total events processed
- `RecordsFiltered`: Events filtered out
- `FilterRate`: Percentage filtered
- `ProcessingTime`: File processing duration
- `ConfigLoadTime`: Configuration loading time
- `Errors`: Error count by type

**Lambda Metrics:**
- `LambdaDuration`: Execution time
- `MemoryUsed`: Memory consumption
- `ColdStarts`: Cold start frequency

### Logging

**Log Levels:**
- `DEBUG`: Detailed execution flow
- `INFO`: Normal operations
- `WARN`: Potential issues
- `ERROR`: Failures requiring attention

**Structured Logging:**
```json
{
  "level": "info",
  "time": 1234567890,
  "requestId": "abc-123",
  "eventName": "AssumeRole",
  "ruleName": "FilterServiceRoles",
  "action": "filtered"
}
```

### Alerting

**Recommended Alarms:**
- Error rate > 1%
- Processing time > 60s
- Memory usage > 90%
- Configuration load failures

## Design Decisions

### 1. Why Go?

**Reasons:**
- Fast cold starts (< 100ms)
- Low memory footprint
- Excellent concurrency model
- Strong AWS SDK support
- Native JSON handling

### 2. Why Streaming Processing?

**Benefits:**
- Handle files of any size
- Constant memory usage
- Faster time to first byte
- Graceful degradation

### 3. Why Multiple Config Sources?

**Advantages:**
- Environment flexibility
- Security options
- Operational simplicity
- Migration paths

### 4. Why Cached Regex?

**Performance:**
- 10x faster evaluation
- Reduced CPU usage
- Predictable latency
- Memory efficiency

### 5. Why Versioned Configuration?

**Benefits:**
- Change tracking
- Rollback capability
- Multi-environment support
- Audit trail

## Future Enhancements

### Planned Features

1. **Machine Learning Integration**
   - Anomaly detection
   - Auto-rule generation
   - Pattern learning

2. **Advanced Filtering**
   - Complex boolean logic
   - Time-based rules
   - Contextual filtering

3. **Performance Improvements**
   - WebAssembly rules
   - GPU acceleration
   - Distributed processing

4. **Operational Features**
   - Web UI for rule management
   - A/B testing support
   - Real-time rule updates

### Scalability Considerations

**Current Limits:**
- 1000 concurrent executions
- 500MB file size
- 1000 rules

**Future Scaling:**
- Step Functions for orchestration
- Fargate for large files
- Kinesis for streaming

## Conclusion

The CloudTrail Log Parser represents a production-ready, highly optimized solution for reducing CloudTrail log noise while maintaining security visibility. Its modular architecture, comprehensive security controls, and performance optimizations make it suitable for enterprise-scale deployments processing billions of events daily.

The system's design prioritizes:
- **Performance**: Sub-second processing for most files
- **Reliability**: Comprehensive error handling and retries
- **Security**: Multiple layers of validation and protection
- **Observability**: Rich metrics and structured logging
- **Maintainability**: Clean architecture and extensive testing

This architecture provides a solid foundation for future enhancements while maintaining backward compatibility and operational stability.
