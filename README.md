# CloudTrail Log Parser

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange?style=flat&logo=amazon-aws)](https://aws.amazon.com/lambda/)

A high-performance, cost-optimized CloudTrail log processor designed to filter and reduce noise in AWS CloudTrail logs before they reach your SIEM or logging infrastructure. This solution can significantly reduce logging costs by filtering out unnecessary events while maintaining security and compliance requirements.

> **Credits**: Based on the excellent work by [Mark Wolfe](https://github.com/wolfeidau) and his [cloudtrail-log-processor](https://github.com/wolfeidau/cloudtrail-log-processor/tree/master) project, enhanced with Lambda optimizations, modular configuration, and enterprise features.

## Key Benefits

- **Cost Reduction**: Filter up to 80% of noise from CloudTrail logs, reducing SIEM ingestion costs
- **Performance**: Process gigabytes of CloudTrail logs in seconds with streaming JSON
- **Flexibility**: Load filtering rules from multiple sources (S3, SSM, Secrets Manager)
- **Reliability**: Built-in retry logic, circuit breakers, and comprehensive error handling
- **Security**: ReDoS protection, input validation, and secure secrets management
- **Observability**: Rich CloudWatch metrics for monitoring and alerting

## 📚 Documentation

Comprehensive documentation is available for different use cases:

| Document                                 | Description                                                        | Audience                          |
| ---------------------------------------- | ------------------------------------------------------------------ | --------------------------------- |
| [ARCHITECTURE.md](ARCHITECTURE.md)       | System design, architectural decisions, and component interactions | Architects, Senior Engineers      |
| [API_REFERENCE.md](API_REFERENCE.md)     | Complete API documentation, data structures, and interfaces        | Developers, Integration Engineers |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | Development setup, examples, and best practices                    | Developers, Contributors          |
| [DEPLOYMENT.md](DEPLOYMENT.md)           | Production deployment, operations, and monitoring                  | DevOps, SRE Teams                 |

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or higher
- AWS account with appropriate IAM permissions
- AWS CLI configured
- (Optional) Terraform/CloudFormation/CDK for infrastructure deployment

### Local Development

1. **Clone the repository**:
```bash
git clone https://github.com/boogy/cloudtrail-log-parser.git
cd cloudtrail-log-parser
```

2. **Install dependencies**:
```bash
go mod download
```

3. **Create a basic rules configuration** (`rules.yaml`):
```yaml
version: 1.0.0
rules:
  - name: Filter KMS decrypt operations
    matches:
      - field_name: eventName
        regex: "^Decrypt$"
      - field_name: eventSource
        regex: "kms.amazonaws.com"
```

4. **Run locally**:
```bash
# Set required environment variables
export CLOUDTRAIL_OUTPUT_BUCKET_NAME=my-filtered-logs-bucket
export CONFIG_FILE=./rules.yaml

# Run the processor
go run ./cmd/main.go
```

### Lambda Deployment

1. **Build the Lambda package**:
```bash
make build-lambda
# Or manually:
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -tags=lambda.norpc -o bootstrap ./cmd/
zip lambda.zip bootstrap
```

2. **Deploy using your preferred IaC tool** (see [DEPLOYMENT.md](DEPLOYMENT.md) for detailed examples)

3. **Configure SNS/S3 triggers** to invoke the Lambda function

## Features

### Core Capabilities

- **Modular Configuration Loading**: Load rules from S3, SSM Parameter Store, Secrets Manager, or local files
- **Configuration Caching**: Reduce cold starts with intelligent configuration caching
- **Streaming JSON Processing**: Memory-efficient processing for large CloudTrail files
- **Exponential Backoff Retry**: Automatic retry logic for transient failures
- **CloudWatch Metrics**: Comprehensive metrics for monitoring and alerting
- **Configuration Versioning**: Support for versioned configurations with validation
- **Lambda Optimizations**: Cold start optimizations and connection pooling
- **ReDoS Protection**: Protection against Regular Expression Denial of Service attacks

## 📁 Project Structure

```
cloudtrail-log-parser/
├── cmd/                    # Application entrypoint
│   └── main.go            # Lambda handler and initialization
├── pkg/              # Internal packages
│   ├── config/           # Configuration management
│   ├── filter/           # CloudTrail event filtering logic
│   ├── metrics/          # CloudWatch metrics
│   ├── processor/        # Log processing engine
│   └── rules/            # Rule evaluation engine
├── pkg/                   # Public packages
│   ├── cloudtrail/       # CloudTrail event models
│   └── utils/            # Utility functions
├── test/                  # Integration tests
├── examples/             # Example configurations
└── scripts/              # Build and deployment scripts
```

## Configuration

### Environment Variables

The service is configured through environment variables, organized by functional area:

#### Core Configuration

| Variable                        | Required | Description                                      | Default |
| ------------------------------- | -------- | ------------------------------------------------ | ------- |
| `CLOUDTRAIL_OUTPUT_BUCKET_NAME` | ✅        | S3 bucket for filtered events                    | -       |
| `SNS_PAYLOAD_TYPE`              | ❌        | Payload type from SNS (`s3` or `cloudtrail`)     | `s3`    |
| `SNS_TOPIC_ARN`                 | ❌        | SNS topic ARN for event broadcasting             | -       |
| `SQS_QUEUE_URL`                 | ❌        | SQS queue URL for event broadcasting             | -       |
| `MULTIPART_DOWNLOAD`            | ❌        | Enable S3 multipart download                     | `false` |
| `LOG_LEVEL`                     | ❌        | Logging level (`debug`, `info`, `warn`, `error`) | `warn`  |

#### Configuration Source

| Variable        | Description                                                   | Default |
| --------------- | ------------------------------------------------------------- | ------- |
| `CONFIG_SOURCE` | Configuration source (`local`, `s3`, `ssm`, `secretsmanager`) | `local` |

**Source-specific variables:**

<details>
<summary>S3 Configuration</summary>

| Variable           | Description                        |
| ------------------ | ---------------------------------- |
| `CONFIG_S3_BUCKET` | S3 bucket containing configuration |
| `CONFIG_S3_KEY`    | S3 key for configuration file      |
| `CONFIG_S3_PATH`   | Alternative format: `bucket/key`   |

</details>

<details>
<summary>SSM Parameter Store</summary>

| Variable               | Description                                 |
| ---------------------- | ------------------------------------------- |
| `CONFIG_SSM_PARAMETER` | SSM parameter name containing configuration |

</details>

<details>
<summary>Secrets Manager</summary>

| Variable           | Description                                        |
| ------------------ | -------------------------------------------------- |
| `CONFIG_SECRET_ID` | Secrets Manager secret ID containing configuration |

</details>

<details>
<summary>Local File</summary>

| Variable      | Description                   | Default        |
| ------------- | ----------------------------- | -------------- |
| `CONFIG_FILE` | Local configuration file path | `./rules.yaml` |

</details>

#### Performance & Monitoring

| Variable                  | Description                  | Default            |
| ------------------------- | ---------------------------- | ------------------ |
| `CONFIG_CACHE_ENABLED`    | Enable configuration caching | `true`             |
| `CONFIG_REFRESH_INTERVAL` | Cache refresh interval       | `5m`               |
| `METRICS_ENABLED`         | Enable CloudWatch metrics    | `true`             |
| `METRICS_NAMESPACE`       | CloudWatch metrics namespace | `CloudTrailFilter` |

### Rule Configuration Format

The service uses YAML-based rule configurations. See [API_REFERENCE.md](API_REFERENCE.md) for complete schema documentation.

#### Basic Configuration
```yaml
rules:
  - name: Filter read-only operations
    matches:
      - field_name: eventName
        regex: "^(Get|List|Describe).*"
```

#### Versioned Configuration (Recommended)
```yaml
version: 1.0.0
meta:
  description: Production CloudTrail filtering rules
  author: security-team
  updated_at: 2024-01-15
rules:
  - name: Filter KMS Events from EKS
    matches:
      - field_name: eventName
        regex: "^(Decrypt|Encrypt|Sign)$"
      - field_name: eventSource
        regex: "kms.*"
      - field_name: sourceIPAddress
        regex: "^eks.amazonaws.com$"
```

## 📖 Examples

### Common Filtering Scenarios

#### 1. Filter High-Volume AWS Service Events
```yaml
# Remove noise from automated AWS services
rules:
  - name: Filter AWS Config Describe calls
    matches:
      - field_name: userIdentity.principalId
        regex: "^AIDAI.*"
      - field_name: userIdentity.invokedBy
        regex: "config.amazonaws.com"
      - field_name: eventName
        regex: "^Describe.*"

  - name: Filter CloudFormation drift detection
    matches:
      - field_name: userIdentity.invokedBy
        regex: "cloudformation.amazonaws.com"
      - field_name: eventName
        regex: "^(Get|List|Describe).*"
```

#### 2. Filter EKS/Kubernetes Service Account Activity
```yaml
# Reduce noise from EKS service accounts
rules:
  - name: Filter EKS KMS operations
    matches:
      - field_name: sourceIPAddress
        regex: "^eks.amazonaws.com$"
      - field_name: eventSource
        regex: "kms.amazonaws.com"

  - name: Filter pod service account calls
    matches:
      - field_name: userIdentity.sessionContext.sessionIssuer.arn
        regex: ".*assumed-role/eks-.*-node/.*"
      - field_name: eventName
        regex: "^(AssumeRole|GetSessionToken)$"
```

#### 3. Filter Read-Only Operations by Service
```yaml
# Keep only write operations for cost optimization
rules:
  - name: Filter all read operations except from specific users
    matches:
      - field_name: eventName
        regex: "^(Get|List|Describe|Head).*"
      - field_name: userIdentity.type
        regex: "^(AssumedRole|Role)$"
    exclude_matches:  # Optional: exceptions to the rule
      - field_name: userIdentity.principalId
        regex: "^(AIDAI.*SECURITY|AIDAI.*AUDIT).*"
```

#### 4. Filter Based on Request Parameters
```yaml
# Advanced filtering using request parameters
rules:
  - name: Filter specific S3 bucket operations
    matches:
      - field_name: eventSource
        regex: "s3.amazonaws.com"
      - field_name: requestParameters.bucketName
        regex: "^(logs-|temp-|cache-).*"
      - field_name: eventName
        regex: "^(GetObject|HeadObject)$"
```

### Rule Matching Logic

- **Within a rule**: ALL matches must be true (AND logic)
- **Between rules**: ANY rule match filters the event (OR logic)
- **Field paths**: Support nested JSON paths (e.g., `userIdentity.sessionContext.sessionIssuer.arn`)

For more examples and advanced configurations, see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).

## Deployment

### AWS Lambda Deployment

For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

#### Quick Deploy Options

##### Option 1: Use Pre-built Lambda ZIP from Releases

Download the Lambda-ready ZIP package directly from [GitHub Releases](https://github.com/boogy/cloudtrail-log-parser/releases):
- `cloudtrail-log-parser-lambda_<version>_linux_amd64.zip` - For x86_64 Lambda functions
- `cloudtrail-log-parser-lambda_<version>_linux_arm64.zip` - For ARM64 (Graviton2) Lambda functions

These ZIPs contain the `bootstrap` binary ready for AWS Lambda deployment.

##### Option 2: Use Docker Images for Lambda

Docker images are published to both GitHub Container Registry and Docker Hub for direct use with AWS Lambda Container Image support:

**GitHub Container Registry:**
```bash
# Latest version
ghcr.io/boogy/cloudtrail-log-parser:latest

# Specific version
ghcr.io/boogy/cloudtrail-log-parser:v1.0.0
```

**Docker Hub:**
```bash
# Latest version
docker.io/boogy/cloudtrail-log-parser:latest

# Specific version  
docker.io/boogy/cloudtrail-log-parser:v1.0.0
```

Deploy Lambda using container image:
```bash
aws lambda create-function \
  --function-name cloudtrail-log-parser \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/cloudtrail-log-parser:latest \
  --role arn:aws:iam::123456789012:role/lambda-role \
  --architectures arm64  # or x86_64
```

##### Option 3: Build from Source

1. **Build the Lambda package**:
```bash
# Using make (recommended)
make build-lambda

# Or manually
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-s -w" \
  -tags=lambda.norpc \
  -o bootstrap ./cmd/
zip lambda.zip bootstrap
```

2. **Deploy using IaC** (examples in [DEPLOYMENT.md](DEPLOYMENT.md)):
   - Terraform
   - CloudFormation
   - AWS CDK
   - Serverless Framework

3. **Configure triggers**:
   - S3 event notifications
   - SNS topic subscriptions
   - EventBridge rules

#### Recommended Lambda Configuration

| Setting                   | Recommended Value | Notes                          |
| ------------------------- | ----------------- | ------------------------------ |
| **Memory**                | 1024-2048 MB      | Adjust based on log file sizes |
| **Timeout**               | 5 minutes         | Increase for large files       |
| **Architecture**          | ARM64 (Graviton2) | 20% cost savings               |
| **Runtime**               | provided.al2      | Custom runtime for Go          |
| **Concurrent Executions** | 100-500           | Based on expected load         |
| **Reserved Concurrency**  | Optional          | For predictable performance    |
| **Dead Letter Queue**     | Recommended       | For failed processing          |

#### Required IAM Permissions

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete IAM policy examples. Minimum required:
- S3: GetObject on source bucket, PutObject on destination bucket
- CloudWatch: PutMetricData (if metrics enabled)
- SNS/SQS: Publish permissions (if configured)
- Config source permissions (SSM/Secrets Manager/S3)

## 📊 Monitoring & Metrics

### CloudWatch Metrics

The service publishes comprehensive metrics to CloudWatch:

| Metric                | Description              | Use Case                     |
| --------------------- | ------------------------ | ---------------------------- |
| `RecordsProcessed`    | Total events processed   | Track throughput             |
| `RecordsFiltered`     | Events filtered out      | Measure filter effectiveness |
| `FilterRate`          | Percentage filtered      | Cost savings indicator       |
| `ProcessingTime`      | File processing duration | Performance monitoring       |
| `ConfigLoadTime`      | Config load duration     | Cold start analysis          |
| `S3OperationDuration` | S3 operation latency     | Network performance          |
| `Errors`              | Error counts by type     | Reliability tracking         |
| `LambdaDuration`      | Total execution time     | Cost optimization            |
| `MemoryUsed`          | Memory consumption       | Right-sizing                 |

### Monitoring Best Practices

1. **Set up CloudWatch Alarms** for:
   - High error rates (> 1%)
   - Processing time anomalies
   - Memory usage > 80%
   - Filter rate changes

2. **Create CloudWatch Dashboard** with:
   - Real-time metrics visualization
   - Cost savings calculations
   - Performance trends

3. **Enable X-Ray tracing** for:
   - Distributed tracing
   - Performance bottleneck identification
   - Service map visualization

## 🧪 Testing

### Run Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make bench

# Race condition detection
go test -race ./...

# Integration tests
make test-integration
```

### Test Coverage Areas

- Unit tests for all rule engines
- Integration tests for AWS services
- Benchmark tests for performance validation
- Fuzz testing for regex patterns
- Load testing for scalability

## ⚡ Performance Optimizations

### Built-in Optimizations

1. **Cold Start Reduction**
   - Global AWS client initialization
   - Configuration pre-loading and caching
   - Connection pooling with keep-alive
   - Optimized binary size with build flags

2. **Memory Efficiency**
   - Streaming JSON processing (no full file load)
   - Object pooling for frequent allocations
   - Efficient GZIP handling
   - Minimal memory allocations

3. **Processing Speed**
   - Pre-compiled regex patterns
   - Parallel processing where applicable
   - Early exit on rule matches
   - Optimized JSON path traversal

4. **Resilience**
   - Exponential backoff with jitter
   - Circuit breaker for downstream services
   - Graceful degradation
   - Comprehensive error handling

## 🔒 Security

### Security Features

- **ReDoS Protection**: Automatic validation of regex patterns
- **Input Validation**: Comprehensive sanitization of all inputs
- **Path Traversal Protection**: Secure file path handling
- **Secrets Management**: Integration with AWS Secrets Manager/SSM
- **Least Privilege**: Minimal IAM permissions required
- **Audit Logging**: Detailed logging for security events

### Security Best Practices

1. **Use versioned configurations** for audit trails
2. **Store sensitive rules** in Secrets Manager
3. **Enable CloudTrail** for the Lambda function itself
4. **Regularly update dependencies** for security patches
5. **Use VPC endpoints** for private S3 access

## 🔧 Troubleshooting

### Common Issues

<details>
<summary>Lambda timeout errors</summary>

**Symptoms**: Function times out before completion

**Solutions**:
- Increase Lambda timeout (max 15 minutes)
- Enable multipart download for large files
- Reduce file size by splitting CloudTrail logs
- Increase Lambda memory for faster processing

</details>

<details>
<summary>Configuration not loading</summary>

**Symptoms**: Rules not being applied

**Solutions**:
- Check IAM permissions for config source
- Verify environment variables are set correctly
- Check CloudWatch logs for error messages
- Validate YAML syntax in configuration

</details>

<details>
<summary>High memory usage</summary>

**Symptoms**: Lambda running out of memory

**Solutions**:
- Enable streaming mode (MULTIPART_DOWNLOAD=true)
- Increase Lambda memory allocation
- Check for regex patterns causing backtracking
- Review CloudWatch metrics for memory patterns

</details>

<details>
<summary>Metrics not appearing</summary>

**Symptoms**: No metrics in CloudWatch

**Solutions**:
- Ensure METRICS_ENABLED=true
- Check IAM permissions for cloudwatch:PutMetricData
- Verify METRICS_NAMESPACE is valid
- Check CloudWatch Logs for metric errors

</details>

For more troubleshooting help, see [DEPLOYMENT.md](DEPLOYMENT.md) or open an issue.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Contribution Guidelines

- **Code Quality**: Follow Go best practices and maintain test coverage above 80%
- **Documentation**: Update relevant documentation for any API changes
- **Security**: Consider security implications and add appropriate validation
- **Performance**: Benchmark significant changes and document impacts
- **Testing**: Add unit and integration tests for new features

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Based on original work by [Mark Wolfe](https://github.com/wolfeidau) - [cloudtrail-log-processor](https://github.com/wolfeidau/cloudtrail-log-processor).

## 🙏 Acknowledgments

- [Mark Wolfe](https://github.com/wolfeidau) for the original cloudtrail-log-processor

## 📬 Support

- **Documentation**: See the [documentation section](#-documentation) above
- **Issues**: [GitHub Issues](https://github.com/boogy/cloudtrail-log-parser/issues)

---

<p align="center">
  Made with ❤️ for the AWS community
</p>
