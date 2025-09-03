# CloudTrail Log Parser - Developer Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Setup](#development-setup)
3. [Understanding CloudTrail Logs](#understanding-cloudtrail-logs)
4. [Writing Filter Rules](#writing-filter-rules)
5. [Testing and Debugging](#testing-and-debugging)
6. [Common Use Cases](#common-use-cases)
7. [Performance Tuning](#performance-tuning)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)

## Getting Started

### Prerequisites

- Go 1.22 or higher
- AWS CLI configured with appropriate credentials
- Docker (optional, for local Lambda testing)
- Make (for build automation)

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/your-org/cloudtrail-log-parser.git
cd cloudtrail-log-parser
```

2. **Install dependencies:**
```bash
go mod download
go mod verify
```

3. **Run tests:**
```bash
make test
```

4. **Build for Lambda:**
```bash
make build-lambda
```

5. **Run locally for testing:**
```bash
# Set required environment variables
export CLOUDTRAIL_OUTPUT_BUCKET_NAME="your-output-bucket"
export CONFIG_FILE="./rules-example.yaml"
export LOG_LEVEL="debug"

# Run with sample event
go run cmd/main.go < examples/sns-event.json
```

## Development Setup

### Project Structure

```
cloudtrail-log-parser/
├── cmd/
│   ├── main.go              # Lambda handler
│   ├── dev.go               # Development mode
│   └── config-export/       # Configuration utilities
├── pkg/
│   ├── cloudtrailprocessor/ # Core processing
│   ├── config/              # Configuration management
│   ├── rules/               # Rule engine
│   ├── processor/           # Streaming processor
│   ├── metrics/             # CloudWatch metrics
│   └── utils/               # Utilities
├── examples/
│   ├── cloudtrail.json      # Sample CloudTrail log
│   └── rules/               # Example rule files
├── scripts/
│   └── build-lambda.sh      # Build script
├── Makefile                 # Build automation
└── go.mod                   # Go dependencies
```

### Local Development Environment

#### Using Docker for Lambda Testing

```dockerfile
# Dockerfile.dev
FROM public.ecr.aws/lambda/provided:al2-x86_64

COPY bootstrap ${LAMBDA_RUNTIME_DIR}
COPY rules.yaml /var/task/

CMD ["bootstrap"]
```

Build and run:
```bash
# Build the binary
GOOS=linux GOARCH=amd64 go build -o bootstrap cmd/main.go

# Build Docker image
docker build -f Dockerfile.dev -t cloudtrail-parser .

# Run locally
docker run -p 9000:8080 \
  -e CLOUDTRAIL_OUTPUT_BUCKET_NAME=test-bucket \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION=us-east-1 \
  cloudtrail-parser

# Test with curl
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
  -d @examples/sns-event.json
```

#### Development Mode

Enable development mode for additional debugging:

```go
// cmd/dev.go
//go:build dev
// +build dev

package main

import (
    "context"
    "encoding/json"
    "os"
)

func main() {
    // Read event from stdin
    var event interface{}
    json.NewDecoder(os.Stdin).Decode(&event)
    
    // Process with verbose logging
    result, err := OptimizedHandler(context.Background(), event)
    if err != nil {
        panic(err)
    }
    
    // Pretty print result
    json.NewEncoder(os.Stdout).Encode(result)
}
```

Run in development mode:
```bash
go run -tags dev cmd/main.go cmd/dev.go < event.json
```

## Understanding CloudTrail Logs

### CloudTrail Event Structure

CloudTrail logs are JSON documents containing arrays of audit events:

```json
{
  "Records": [
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AIDAI23HXD2O5EXAMPLE",
        "arn": "arn:aws:sts::123456789012:assumed-role/role-name/session-name",
        "accountId": "123456789012",
        "sessionContext": {
          "sessionIssuer": {
            "type": "Role",
            "principalId": "AIDAI23HXD2O5EXAMPLE",
            "arn": "arn:aws:iam::123456789012:role/role-name"
          }
        }
      },
      "eventTime": "2024-01-15T12:34:56Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "GetObject",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "203.0.113.0",
      "userAgent": "aws-cli/2.13.0",
      "requestParameters": {
        "bucketName": "my-bucket",
        "key": "my-file.txt"
      },
      "responseElements": null,
      "requestID": "EXAMPLE123456789",
      "eventID": "12345678-1234-1234-1234-123456789012",
      "readOnly": true,
      "eventType": "AwsApiCall",
      "recipientAccountId": "123456789012"
    }
  ]
}
```

### Common Field Paths

Use these paths in your filter rules:

```yaml
# Top-level fields
eventName           # API action name
eventSource         # AWS service domain
awsRegion          # AWS region
sourceIPAddress    # Client IP address
userAgent          # Client user agent
errorCode          # Error code if failed
readOnly           # Read-only operation flag

# User identity fields
userIdentity.type                                    # Identity type
userIdentity.principalId                            # Principal ID
userIdentity.arn                                     # User/role ARN
userIdentity.accountId                              # Account ID
userIdentity.sessionContext.sessionIssuer.arn       # Session issuer ARN
userIdentity.sessionContext.sessionIssuer.type      # Session issuer type

# Request/Response fields
requestParameters.*                                  # Request parameters
responseElements.*                                   # Response data
resources[].arn                                     # Resource ARNs
```

## Writing Filter Rules

### Basic Rule Structure

Rules use regex patterns to match CloudTrail event fields:

```yaml
version: "1.0.0"
meta:
  description: "Filter rules for production environment"
  author: "security-team"
rules:
  - name: "Descriptive Rule Name"
    matches:
      - field_name: "eventName"
        regex: "^GetObject$"
      - field_name: "eventSource"
        regex: "^s3\\.amazonaws\\.com$"
```

### Rule Logic

- **Within a rule:** ALL matches must be true (AND logic)
- **Between rules:** ANY rule match filters the event (OR logic)

### Example Rules

#### 1. Filter High-Volume Read Operations

```yaml
rules:
  - name: "Filter S3 Read Operations"
    matches:
      - field_name: "eventName"
        regex: "^(GetObject|HeadObject|ListObjects)$"
      - field_name: "eventSource"
        regex: "^s3\\.amazonaws\\.com$"
      - field_name: "readOnly"
        regex: "^true$"
```

#### 2. Filter Service-to-Service Communications

```yaml
rules:
  - name: "Filter EKS to KMS Operations"
    matches:
      - field_name: "eventSource"
        regex: "^kms\\.amazonaws\\.com$"
      - field_name: "sourceIPAddress"
        regex: "^eks\\.amazonaws\\.com$"
      - field_name: "eventName"
        regex: "^(Decrypt|Encrypt|GenerateDataKey)$"
```

#### 3. Filter by User Identity

```yaml
rules:
  - name: "Filter Service Role Assumptions"
    matches:
      - field_name: "eventName"
        regex: "^AssumeRole$"
      - field_name: "userIdentity.sessionContext.sessionIssuer.arn"
        regex: ".*:role/aws-service-role/.*"
```

#### 4. Filter Failed Authentication Attempts

```yaml
rules:
  - name: "Filter Known Failed Auth Patterns"
    matches:
      - field_name: "eventName"
        regex: "^(AssumeRole|GetSessionToken)$"
      - field_name: "errorCode"
        regex: "^(AccessDenied|TokenRefreshRequired)$"
      - field_name: "userAgent"
        regex: ".*automated-scanner.*"
```

### Advanced Patterns

#### Using Alternation (OR within regex)

```yaml
rules:
  - name: "Multiple Event Names"
    matches:
      - field_name: "eventName"
        regex: "^(CreateBucket|DeleteBucket|PutBucketPolicy)$"
```

#### Partial Matching

```yaml
rules:
  - name: "Contains Pattern"
    matches:
      - field_name: "userAgent"
        regex: ".*terraform.*"  # Contains 'terraform' anywhere
```

#### Negation (Keep everything except)

To keep events, ensure they DON'T match any rule:

```yaml
# This filters OUT everything except EC2 events
rules:
  - name: "Filter Non-EC2"
    matches:
      - field_name: "eventSource"
        regex: "^(?!ec2\\.amazonaws\\.com$).*$"
```

### Rule Testing

#### Dry Run Testing

Test rules against sample events before deployment:

```go
package main

import (
    "context"
    "ctlp/pkg/rules"
    "ctlp/pkg/utils"
    "log"
)

func TestRules() {
    // Load configuration
    cfg, err := rules.LoadFromConfigFile(context.Background(), "rules.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    // Load sample events
    events := []map[string]any{
        utils.ReadTestEvents("examples/cloudtrail.json"),
    }
    
    // Create versioned config for dry run
    versionedCfg := &rules.VersionedConfiguration{
        Version: "1.0.0",
        Rules:   cfg.Rules,
    }
    
    // Run dry run
    result, err := versionedCfg.DryRun(events)
    if err != nil {
        log.Fatal(err)
    }
    
    // Print results
    log.Printf("Total Events: %d", result.TotalEvents)
    log.Printf("Filtered: %d (%.2f%%)", result.FilteredCount, result.FilterRate*100)
    log.Printf("Passed: %d", result.PassedCount)
    
    for rule, count := range result.RuleHits {
        log.Printf("Rule '%s' matched %d events", rule, count)
    }
}
```

## Testing and Debugging

### Unit Testing

#### Testing Filter Rules

```go
package rules_test

import (
    "testing"
    "ctlp/pkg/rules"
)

func TestRuleEvaluation(t *testing.T) {
    // Create a test rule
    rule := &rules.Rule{
        Name: "Test Rule",
        Matches: []*rules.Match{
            {
                FieldName: "eventName",
                Regex:     "^AssumeRole$",
            },
            {
                FieldName: "eventSource",
                Regex:     "^sts\\.amazonaws\\.com$",
            },
        },
    }
    
    // Test matching event
    matchEvent := map[string]any{
        "eventName":   "AssumeRole",
        "eventSource": "sts.amazonaws.com",
    }
    
    match, dropEvent, err := rule.Eval(matchEvent)
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    if !match {
        t.Error("Expected event to match")
    }
    if dropEvent.RuleName != "Test Rule" {
        t.Errorf("Expected rule name 'Test Rule', got '%s'", dropEvent.RuleName)
    }
    
    // Test non-matching event
    nonMatchEvent := map[string]any{
        "eventName":   "GetObject",
        "eventSource": "s3.amazonaws.com",
    }
    
    match, _, err = rule.Eval(nonMatchEvent)
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    if match {
        t.Error("Expected event not to match")
    }
}
```

#### Testing CloudTrail Processing

```go
package cloudtrailprocessor_test

import (
    "context"
    "testing"
    "ctlp/pkg/cloudtrailprocessor"
    "ctlp/pkg/rules"
)

func TestFilterRecords(t *testing.T) {
    // Create test CloudTrail data
    input := &cloudtrailprocessor.Cloudtrail{
        Records: []json.RawMessage{
            json.RawMessage(`{"eventName":"AssumeRole","eventSource":"sts.amazonaws.com"}`),
            json.RawMessage(`{"eventName":"GetObject","eventSource":"s3.amazonaws.com"}`),
        },
    }
    
    // Create test rules
    cfg := &rules.Configuration{
        Rules: []*rules.Rule{
            {
                Name: "Filter AssumeRole",
                Matches: []*rules.Match{
                    {FieldName: "eventName", Regex: "^AssumeRole$"},
                },
            },
        },
    }
    
    // Prepare cached configuration
    cachedCfg, err := rules.PrepareConfiguration(cfg)
    if err != nil {
        t.Fatal(err)
    }
    
    // Filter records
    output, err := cloudtrailprocessor.FilterRecords(
        context.Background(),
        input,
        cachedCfg,
    )
    
    if err != nil {
        t.Fatal(err)
    }
    
    // Verify results
    if len(output.Records) != 1 {
        t.Errorf("Expected 1 record, got %d", len(output.Records))
    }
}
```

### Integration Testing

#### Local S3 Testing with MinIO

```yaml
# docker-compose.yml
version: '3.8'

services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio-data:/data

volumes:
  minio-data:
```

```go
// integration_test.go
func TestS3Integration(t *testing.T) {
    // Configure S3 client for MinIO
    cfg, _ := config.LoadDefaultConfig(context.Background(),
        config.WithEndpointResolverWithOptions(
            aws.EndpointResolverWithOptionsFunc(
                func(service, region string, options ...interface{}) (aws.Endpoint, error) {
                    return aws.Endpoint{
                        URL:           "http://localhost:9000",
                        SigningRegion: "us-east-1",
                    }, nil
                },
            ),
        ),
    )
    
    // Test S3 operations
    copier := cloudtrailprocessor.NewCopier(flags.S3Processor{
        CloudtrailOutputBucketName: "output",
    }, &cfg)
    
    err := copier.Copy(context.Background(), "input", "test.json.gz")
    if err != nil {
        t.Fatal(err)
    }
}
```

### Debugging

#### Enable Debug Logging

```bash
export LOG_LEVEL=debug
```

#### Add Debug Statements

```go
import "github.com/rs/zerolog/log"

func ProcessEvent(ctx context.Context, event map[string]any) error {
    log.Ctx(ctx).Debug().
        Interface("event", event).
        Msg("processing event")
    
    // Process event...
    
    log.Ctx(ctx).Debug().
        Str("eventName", event["eventName"].(string)).
        Bool("filtered", filtered).
        Msg("event evaluation complete")
    
    return nil
}
```

#### Trace Execution

```go
// Add tracing spans
import "runtime/trace"

func ProcessFile(ctx context.Context, file string) error {
    ctx, task := trace.NewTask(ctx, "ProcessFile")
    defer task.End()
    
    trace.WithRegion(ctx, "Download", func() {
        // Download file
    })
    
    trace.WithRegion(ctx, "Filter", func() {
        // Filter records
    })
    
    trace.WithRegion(ctx, "Upload", func() {
        // Upload results
    })
    
    return nil
}
```

## Common Use Cases

### 1. Reduce SIEM Costs

Filter out high-volume, low-value events:

```yaml
rules:
  # Filter read-only operations
  - name: "Read-Only Operations"
    matches:
      - field_name: "readOnly"
        regex: "^true$"
      - field_name: "eventName"
        regex: "^(Get|List|Describe).*"
  
  # Filter health checks
  - name: "ELB Health Checks"
    matches:
      - field_name: "userAgent"
        regex: "ELB-HealthChecker"
```

### 2. Focus on Security Events

Keep only security-relevant events:

```yaml
# Invert logic - filter everything EXCEPT security events
rules:
  - name: "Non-Security Events"
    matches:
      - field_name: "eventName"
        regex: "^(?!(CreateUser|DeleteUser|PutUserPolicy|CreateAccessKey|DeleteAccessKey|CreateRole|DeleteRole|PutRolePolicy|AssumeRole)).*$"
```

### 3. Compliance Filtering

Track specific compliance-related events:

```yaml
rules:
  # Filter out everything except data access
  - name: "Non-Data Access"
    matches:
      - field_name: "eventSource"
        regex: "^(?!(s3|dynamodb|rds)\\.amazonaws\\.com).*"
      - field_name: "eventName"
        regex: "^(?!(GetObject|PutObject|DeleteObject|Query|Scan|GetItem|PutItem)).*"
```

### 4. Environment-Specific Filtering

Different rules for different environments:

```yaml
# dev-rules.yaml - Aggressive filtering for dev
rules:
  - name: "Filter Most Events"
    matches:
      - field_name: "eventSource"
        regex: ".*"
      - field_name: "errorCode"
        regex: "^$"  # No error code (successful operations)

# prod-rules.yaml - Conservative filtering for prod
rules:
  - name: "Filter Only Service Communications"
    matches:
      - field_name: "sourceIPAddress"
        regex: ".*\\.amazonaws\\.com$"
      - field_name: "userIdentity.type"
        regex: "^AWSService$"
```

## Performance Tuning

### 1. Optimize Rule Order

Place most frequently matching rules first:

```yaml
rules:
  # This matches 60% of events - put it first
  - name: "High Volume Rule"
    matches:
      - field_name: "eventName"
        regex: "^Describe.*"
  
  # This matches 20% of events
  - name: "Medium Volume Rule"
    matches:
      - field_name: "eventName"
        regex: "^List.*"
  
  # This matches 5% of events
  - name: "Low Volume Rule"
    matches:
      - field_name: "eventName"
        regex: "^Delete.*"
```

### 2. Optimize Regex Patterns

Use anchors and avoid wildcards when possible:

```yaml
# Good - uses anchors
regex: "^AssumeRole$"

# Bad - no anchors
regex: "AssumeRole"

# Good - specific pattern
regex: "^arn:aws:iam::\\d{12}:role/.*$"

# Bad - too broad
regex: ".*role.*"
```

### 3. Lambda Memory Configuration

Adjust based on file size:

```python
# Terraform example
resource "aws_lambda_function" "parser" {
  memory_size = var.average_file_size_mb < 50 ? 1024 : 
                var.average_file_size_mb < 100 ? 2048 : 
                3008
}
```

### 4. Use Multipart Download

For large files (>50MB):

```bash
export MULTIPART_DOWNLOAD=true
```

### 5. Configuration Caching

Enable caching to reduce configuration load time:

```bash
export CONFIG_CACHE_ENABLED=true
export CONFIG_REFRESH_INTERVAL=10m
```

## Troubleshooting

### Common Issues

#### 1. Lambda Timeout

**Symptom:** Function times out processing large files

**Solutions:**
- Increase Lambda timeout (max 15 minutes)
- Increase Lambda memory
- Enable multipart download
- Consider using Step Functions for very large files

#### 2. High Memory Usage

**Symptom:** Lambda runs out of memory

**Solutions:**
```go
// Use streaming processor instead of batch
processor := processor.NewStreamingProcessor(rules, metrics)
result, err := processor.ProcessStream(ctx, input, output, true)
```

#### 3. Configuration Not Loading

**Symptom:** Rules not being applied

**Debug steps:**
```bash
# Check configuration source
echo $CONFIG_SOURCE

# Test configuration loading
aws s3 cp s3://$CONFIG_S3_BUCKET/$CONFIG_S3_KEY - | cat

# Validate configuration
go run cmd/config-export/main.go validate -f rules.yaml
```

#### 4. Regex Not Matching

**Debug regex patterns:**
```go
package main

import (
    "fmt"
    "regexp"
)

func main() {
    pattern := "^sts\\.amazonaws\\.com$"
    test := "sts.amazonaws.com"
    
    re, err := regexp.Compile(pattern)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Pattern: %s\n", pattern)
    fmt.Printf("Test: %s\n", test)
    fmt.Printf("Matches: %v\n", re.MatchString(test))
}
```

#### 5. Performance Issues

**Enable metrics and analyze:**
```bash
export METRICS_ENABLED=true
export METRICS_NAMESPACE=CloudTrailDebug
```

Check CloudWatch Metrics for:
- Processing time per file
- Memory usage patterns
- Error rates
- Filter efficiency

### Debugging Lambda Cold Starts

```go
// Add timing to init()
var (
    initStart = time.Now()
)

func init() {
    defer func() {
        log.Info().
            Dur("duration", time.Since(initStart)).
            Msg("init completed")
    }()
    
    // Initialization code...
}
```

### Memory Profiling

```go
import (
    "runtime"
    "runtime/pprof"
)

func ProfileMemory() {
    f, _ := os.Create("mem.prof")
    defer f.Close()
    runtime.GC()
    pprof.WriteHeapProfile(f)
}
```

Analyze profile:
```bash
go tool pprof mem.prof
```

## Contributing

### Code Style

Follow Go best practices:
```go
// Good
func ProcessEvent(ctx context.Context, event *CloudTrailEvent) error {
    if event == nil {
        return errors.New("event cannot be nil")
    }
    // Process...
    return nil
}

// Bad
func process_event(event *CloudTrailEvent) {
    // Process...
}
```

### Testing Requirements

- Unit tests for all new functions
- Integration tests for new features
- Benchmark tests for performance-critical code
- Example:

```go
func BenchmarkFilterRecords(b *testing.B) {
    // Setup
    input := loadTestData()
    rules := loadTestRules()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        FilterRecords(context.Background(), input, rules)
    }
}
```

### Documentation

- Add inline comments for complex logic
- Update README for new features
- Add examples for new rule types
- Document breaking changes

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `make test` and `make lint`
5. Update documentation
6. Submit PR with description

### Security Considerations

- Validate all inputs
- Check for ReDoS patterns
- Limit resource consumption
- Follow principle of least privilege
- Never log sensitive data

## Advanced Topics

### Custom Processors

Implement custom processing logic:

```go
type CustomProcessor struct {
    baseProcessor Processor
}

func (cp *CustomProcessor) Process(ctx context.Context, event map[string]any) (bool, error) {
    // Custom logic
    if customCondition(event) {
        return true, nil // Filter out
    }
    
    // Delegate to base processor
    return cp.baseProcessor.Process(ctx, event)
}
```

### Rule Generators

Generate rules programmatically:

```go
func GenerateServiceRules(services []string) *rules.Configuration {
    cfg := &rules.Configuration{
        Rules: make([]*rules.Rule, 0),
    }
    
    for _, service := range services {
        rule := &rules.Rule{
            Name: fmt.Sprintf("Filter %s Events", service),
            Matches: []*rules.Match{
                {
                    FieldName: "eventSource",
                    Regex:     fmt.Sprintf("^%s\\.amazonaws\\.com$", service),
                },
            },
        }
        cfg.Rules = append(cfg.Rules, rule)
    }
    
    return cfg
}
```

### Metrics Extensions

Add custom metrics:

```go
type CustomMetrics struct {
    *metrics.CloudWatchMetrics
    customCounter int
}

func (cm *CustomMetrics) RecordCustomEvent(eventType string) {
    cm.customCounter++
    cm.RecordCustomMetric("CustomEvent", map[string]string{
        "Type": eventType,
    })
}
```

## Conclusion

This guide provides comprehensive information for developing with and extending the CloudTrail Log Parser. For production deployments, see the [Deployment Guide](DEPLOYMENT.md). For API details, see the [API Reference](API_REFERENCE.md).