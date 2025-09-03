# CloudTrail Log Parser - Deployment & Operations Guide

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Prerequisites](#prerequisites)
3. [AWS Lambda Deployment](#aws-lambda-deployment)
4. [Infrastructure as Code](#infrastructure-as-code)
5. [Configuration Management](#configuration-management)
6. [Monitoring Setup](#monitoring-setup)
7. [Operations Runbook](#operations-runbook)
8. [Performance Optimization](#performance-optimization)
9. [Security Best Practices](#security-best-practices)
10. [Disaster Recovery](#disaster-recovery)
11. [Cost Optimization](#cost-optimization)
12. [Maintenance](#maintenance)

## Deployment Overview

### Architecture Components

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ CloudTrail  │───▶│  S3 Source  │───▶│     SNS     │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │     Lambda      │
                                    │   (Parser)      │
                                    └─────────────────┘
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        ▼                     ▼                     ▼
                ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                │ S3 Output   │    │ CloudWatch  │    │  SNS/SQS    │
                │  (Filtered) │    │  Metrics    │    │ (Optional)  │
                └─────────────┘    └─────────────┘    └─────────────┘
```

### Deployment Options

1. **Serverless (Recommended)**: AWS Lambda with SNS triggers
2. **Container**: ECS/Fargate for large-scale processing
3. **Hybrid**: Lambda for real-time, Batch for historical

## Prerequisites

### Required AWS Services

- AWS Lambda
- Amazon S3 (source and destination buckets)
- Amazon SNS
- AWS IAM
- Amazon CloudWatch
- AWS KMS (if using encryption)
- AWS Systems Manager or Secrets Manager (for configuration)

### Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3Operations",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Resource": [
        "arn:aws:s3:::cloudtrail-source-bucket/*",
        "arn:aws:s3:::cloudtrail-output-bucket/*"
      ]
    },
    {
      "Sid": "S3ListBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::cloudtrail-source-bucket",
        "arn:aws:s3:::cloudtrail-output-bucket"
      ]
    },
    {
      "Sid": "KMSOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:CreateGrant"
      ],
      "Resource": "arn:aws:kms:*:*:key/*",
      "Condition": {
        "StringLike": {
          "kms:ViaService": [
            "s3.*.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "CloudWatchMetrics",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/cloudtrail-parser:*"
    },
    {
      "Sid": "ConfigurationAccess",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/cloudtrail-parser/*",
        "arn:aws:secretsmanager:*:*:secret:cloudtrail-parser/*"
      ]
    },
    {
      "Sid": "OptionalSNSSQS",
      "Effect": "Allow",
      "Action": [
        "sns:Publish",
        "sqs:SendMessage"
      ],
      "Resource": [
        "arn:aws:sns:*:*:cloudtrail-filtered-topic",
        "arn:aws:sqs:*:*:cloudtrail-filtered-queue"
      ]
    }
  ]
}
```

### Build Requirements

- Go 1.22+
- AWS CLI
- Make (optional)
- Docker (for container deployments)

## AWS Lambda Deployment

### Step 1: Build the Lambda Package

```bash
# Clone repository
git clone https://github.com/your-org/cloudtrail-log-parser.git
cd cloudtrail-log-parser

# Build for Lambda (ARM64 recommended)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-s -w -X main.Version=$(git rev-parse --short HEAD)" \
  -tags lambda.norpc \
  -o bootstrap \
  cmd/main.go

# Create deployment package
zip -j lambda-deployment.zip bootstrap

# Add configuration file if using local config
zip -u lambda-deployment.zip rules.yaml
```

### Step 2: Create Lambda Function

Using AWS CLI:

```bash
# Create the Lambda function
aws lambda create-function \
  --function-name cloudtrail-log-parser \
  --runtime provided.al2 \
  --architectures arm64 \
  --role arn:aws:iam::123456789012:role/cloudtrail-parser-role \
  --handler bootstrap \
  --zip-file fileb://lambda-deployment.zip \
  --timeout 300 \
  --memory-size 1024 \
  --environment Variables='{
    "CLOUDTRAIL_OUTPUT_BUCKET_NAME":"cloudtrail-filtered",
    "CONFIG_SOURCE":"s3",
    "CONFIG_S3_BUCKET":"config-bucket",
    "CONFIG_S3_KEY":"rules/production.yaml",
    "LOG_LEVEL":"info",
    "METRICS_ENABLED":"true"
  }' \
  --description "CloudTrail log parser and filter"

# Configure SNS trigger
aws lambda add-permission \
  --function-name cloudtrail-log-parser \
  --statement-id sns-trigger \
  --action lambda:InvokeFunction \
  --principal sns.amazonaws.com \
  --source-arn arn:aws:sns:us-east-1:123456789012:cloudtrail-topic

# Subscribe Lambda to SNS topic
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:cloudtrail-topic \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:us-east-1:123456789012:function:cloudtrail-log-parser
```

### Step 3: Configure Reserved Concurrency

```bash
# Set reserved concurrent executions
aws lambda put-function-concurrency \
  --function-name cloudtrail-log-parser \
  --reserved-concurrent-executions 100
```

### Step 4: Configure Provisioned Concurrency (Optional)

```bash
# Create alias
aws lambda create-alias \
  --function-name cloudtrail-log-parser \
  --name production \
  --function-version '$LATEST'

# Configure provisioned concurrency
aws lambda put-provisioned-concurrency-config \
  --function-name cloudtrail-log-parser \
  --qualifier production \
  --provisioned-concurrent-executions 10
```

## Infrastructure as Code

### Terraform Deployment

```hcl
# main.tf

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cloudtrail_source_bucket" {
  description = "Source S3 bucket for CloudTrail logs"
  type        = string
}

variable "cloudtrail_output_bucket" {
  description = "Output S3 bucket for filtered logs"
  type        = string
}

variable "config_s3_path" {
  description = "S3 path for configuration file"
  type        = string
}

# Lambda Function
resource "aws_lambda_function" "parser" {
  filename         = "lambda-deployment.zip"
  function_name    = "cloudtrail-parser-${var.environment}"
  role            = aws_iam_role.lambda_role.arn
  handler         = "bootstrap"
  runtime         = "provided.al2"
  architectures   = ["arm64"]
  timeout         = 300
  memory_size     = 1024
  
  environment {
    variables = {
      CLOUDTRAIL_OUTPUT_BUCKET_NAME = var.cloudtrail_output_bucket
      CONFIG_SOURCE                 = "s3"
      CONFIG_S3_PATH               = var.config_s3_path
      LOG_LEVEL                    = var.environment == "production" ? "info" : "debug"
      METRICS_ENABLED              = "true"
      METRICS_NAMESPACE            = "CloudTrailParser/${var.environment}"
    }
  }
  
  reserved_concurrent_executions = var.environment == "production" ? 100 : 10
  
  tracing_config {
    mode = "Active"
  }
  
  tags = {
    Environment = var.environment
    Service     = "cloudtrail-parser"
    Terraform   = "true"
  }
}

# IAM Role
resource "aws_iam_role" "lambda_role" {
  name = "cloudtrail-parser-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# IAM Policy
resource "aws_iam_role_policy" "lambda_policy" {
  name = "cloudtrail-parser-policy"
  role = aws_iam_role.lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.cloudtrail_source_bucket}/*",
          "arn:aws:s3:::${var.cloudtrail_output_bucket}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/cloudtrail-parser-${var.environment}"
  retention_in_days = var.environment == "production" ? 30 : 7
}

# SNS Topic Subscription
resource "aws_sns_topic_subscription" "lambda_trigger" {
  topic_arn = data.aws_sns_topic.cloudtrail.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.parser.arn
}

# Lambda Permission for SNS
resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.parser.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.aws_sns_topic.cloudtrail.arn
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "cloudtrail-parser-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name        = "Errors"
  namespace          = "AWS/Lambda"
  period             = "300"
  statistic          = "Sum"
  threshold          = "10"
  alarm_description  = "Lambda function errors"
  
  dimensions = {
    FunctionName = aws_lambda_function.parser.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "cloudtrail-parser-duration-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name        = "Duration"
  namespace          = "AWS/Lambda"
  period             = "300"
  statistic          = "Average"
  threshold          = "60000"  # 60 seconds
  alarm_description  = "Lambda function duration"
  
  dimensions = {
    FunctionName = aws_lambda_function.parser.function_name
  }
}

# Outputs
output "lambda_function_arn" {
  value = aws_lambda_function.parser.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.parser.function_name
}
```

### CloudFormation Deployment

```yaml
# cloudtrail-parser.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: CloudTrail Log Parser Lambda Function

Parameters:
  Environment:
    Type: String
    Default: development
    AllowedValues:
      - development
      - staging
      - production
    
  SourceBucket:
    Type: String
    Description: S3 bucket containing CloudTrail logs
    
  OutputBucket:
    Type: String
    Description: S3 bucket for filtered logs
    
  ConfigBucket:
    Type: String
    Description: S3 bucket containing configuration
    
  ConfigKey:
    Type: String
    Description: S3 key for configuration file
    Default: rules.yaml

Resources:
  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub cloudtrail-parser-role-${Environment}
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: CloudTrailParserPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                Resource:
                  - !Sub arn:aws:s3:::${SourceBucket}/*
                  - !Sub arn:aws:s3:::${ConfigBucket}/*
              - Effect: Allow
                Action:
                  - s3:PutObject
                Resource:
                  - !Sub arn:aws:s3:::${OutputBucket}/*
              - Effect: Allow
                Action:
                  - cloudwatch:PutMetricData
                Resource: '*'
                
  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub cloudtrail-parser-${Environment}
      Runtime: provided.al2
      Handler: bootstrap
      Code:
        S3Bucket: !Ref ConfigBucket
        S3Key: lambda/cloudtrail-parser.zip
      Role: !GetAtt LambdaRole.Arn
      Timeout: 300
      MemorySize: 1024
      Architectures:
        - arm64
      Environment:
        Variables:
          CLOUDTRAIL_OUTPUT_BUCKET_NAME: !Ref OutputBucket
          CONFIG_SOURCE: s3
          CONFIG_S3_BUCKET: !Ref ConfigBucket
          CONFIG_S3_KEY: !Ref ConfigKey
          LOG_LEVEL: !If [IsProduction, info, debug]
          METRICS_ENABLED: 'true'
      ReservedConcurrentExecutions: !If [IsProduction, 100, 10]
      
  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/cloudtrail-parser-${Environment}
      RetentionInDays: !If [IsProduction, 30, 7]
      
  LambdaErrorAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub cloudtrail-parser-errors-${Environment}
      MetricName: Errors
      Namespace: AWS/Lambda
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 2
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref LambdaFunction
          
Conditions:
  IsProduction: !Equals [!Ref Environment, production]
  
Outputs:
  LambdaFunctionArn:
    Description: Lambda Function ARN
    Value: !GetAtt LambdaFunction.Arn
    Export:
      Name: !Sub ${AWS::StackName}-lambda-arn
```

## Configuration Management

### Configuration Sources

#### 1. S3 Configuration

```bash
# Upload configuration to S3
aws s3 cp rules-production.yaml s3://config-bucket/cloudtrail-parser/rules.yaml

# Set Lambda environment variables
export CONFIG_SOURCE=s3
export CONFIG_S3_BUCKET=config-bucket
export CONFIG_S3_KEY=cloudtrail-parser/rules.yaml
```

#### 2. SSM Parameter Store

```bash
# Store configuration in SSM
aws ssm put-parameter \
  --name /cloudtrail-parser/production/rules \
  --value file://rules-production.yaml \
  --type SecureString \
  --key-id alias/aws/ssm

# Set Lambda environment variables
export CONFIG_SOURCE=ssm
export CONFIG_SSM_PARAMETER=/cloudtrail-parser/production/rules
```

#### 3. AWS Secrets Manager

```bash
# Store configuration in Secrets Manager
aws secretsmanager create-secret \
  --name cloudtrail-parser/production/rules \
  --secret-string file://rules-production.yaml

# Set Lambda environment variables
export CONFIG_SOURCE=secretsmanager
export CONFIG_SECRET_ID=cloudtrail-parser/production/rules
```

### Configuration Versioning

```yaml
# rules-v1.0.0.yaml
version: "1.0.0"
meta:
  description: "Production rules Q1 2024"
  author: "security-team"
  created_at: "2024-01-01"
rules:
  - name: "Filter Service Communications"
    # ... rules
```

### Configuration Validation

```bash
# Validate configuration before deployment
go run cmd/config-export/main.go validate -f rules.yaml

# Test configuration with dry run
go run cmd/config-export/main.go dryrun \
  -f rules.yaml \
  -e examples/cloudtrail.json
```

## Monitoring Setup

### CloudWatch Dashboard

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["CloudTrailParser", "RecordsProcessed", {"stat": "Sum"}],
          [".", "RecordsFiltered", {"stat": "Sum"}],
          [".", "FilterRate", {"stat": "Average"}]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "Processing Metrics"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Lambda", "Duration", {"FunctionName": "cloudtrail-parser"}],
          [".", "Errors", {"FunctionName": "cloudtrail-parser"}],
          [".", "Throttles", {"FunctionName": "cloudtrail-parser"}]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "Lambda Metrics"
      }
    }
  ]
}
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `RecordsProcessed` | Total events processed | N/A |
| `RecordsFiltered` | Events filtered out | N/A |
| `FilterRate` | Percentage filtered | < 50% (too low) |
| `ProcessingTime` | Time to process file | > 60s |
| `Errors` | Processing errors | > 1% of invocations |
| `LambdaDuration` | Execution time | > 60s average |
| `MemoryUsed` | Memory consumption | > 90% allocated |
| `ConfigLoadTime` | Config loading time | > 5s |

### CloudWatch Alarms

```bash
# Create alarm for high error rate
aws cloudwatch put-metric-alarm \
  --alarm-name cloudtrail-parser-error-rate \
  --alarm-description "High error rate in CloudTrail parser" \
  --metric-name Errors \
  --namespace CloudTrailParser \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2

# Create alarm for low filter rate
aws cloudwatch put-metric-alarm \
  --alarm-name cloudtrail-parser-low-filter-rate \
  --alarm-description "Filter rate too low" \
  --metric-name FilterRate \
  --namespace CloudTrailParser \
  --statistic Average \
  --period 900 \
  --threshold 30 \
  --comparison-operator LessThanThreshold \
  --evaluation-periods 3
```

## Operations Runbook

### Daily Operations

#### Health Check

```bash
# Check Lambda function status
aws lambda get-function \
  --function-name cloudtrail-log-parser \
  --query 'Configuration.[State,LastUpdateStatus]'

# Check recent invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=cloudtrail-log-parser \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### Performance Review

```bash
# Check processing metrics
aws cloudwatch get-metric-statistics \
  --namespace CloudTrailParser \
  --metric-name ProcessingTime \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Average,Maximum
```

### Incident Response

#### High Error Rate

1. **Check Lambda logs:**
```bash
aws logs tail /aws/lambda/cloudtrail-log-parser --follow
```

2. **Identify error pattern:**
```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/cloudtrail-log-parser \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000
```

3. **Common fixes:**
- Increase Lambda memory
- Increase timeout
- Check S3 permissions
- Validate configuration

#### Performance Degradation

1. **Check metrics:**
```bash
# Duration metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=cloudtrail-log-parser \
  --statistics Average,Maximum \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300
```

2. **Analyze cold starts:**
```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/cloudtrail-log-parser \
  --filter-pattern "REPORT" | \
  grep -E "Init Duration"
```

3. **Optimization steps:**
- Enable provisioned concurrency
- Increase memory allocation
- Optimize configuration loading

### Rollback Procedures

#### Lambda Function Rollback

```bash
# List function versions
aws lambda list-versions-by-function \
  --function-name cloudtrail-log-parser

# Update alias to previous version
aws lambda update-alias \
  --function-name cloudtrail-log-parser \
  --name production \
  --function-version 5  # Previous stable version
```

#### Configuration Rollback

```bash
# S3 configuration rollback
aws s3 cp s3://config-bucket/cloudtrail-parser/rules-previous.yaml \
  s3://config-bucket/cloudtrail-parser/rules.yaml

# SSM parameter rollback
aws ssm get-parameter-history \
  --name /cloudtrail-parser/production/rules

aws ssm put-parameter \
  --name /cloudtrail-parser/production/rules \
  --value "$(aws ssm get-parameter \
    --name /cloudtrail-parser/production/rules \
    --version 2 \
    --query 'Parameter.Value' \
    --output text)" \
  --overwrite
```

## Performance Optimization

### Lambda Optimization

#### Memory Configuration

```python
# Recommended memory settings based on file size
def calculate_memory(avg_file_size_mb):
    if avg_file_size_mb < 10:
        return 512
    elif avg_file_size_mb < 50:
        return 1024
    elif avg_file_size_mb < 100:
        return 2048
    else:
        return 3008
```

#### Concurrency Settings

```bash
# Set reserved concurrency based on load
aws lambda put-function-concurrency \
  --function-name cloudtrail-log-parser \
  --reserved-concurrent-executions 100

# Configure provisioned concurrency for predictable load
aws lambda put-provisioned-concurrency-config \
  --function-name cloudtrail-log-parser \
  --qualifier production \
  --provisioned-concurrent-executions 20
```

### S3 Optimization

#### Multipart Download

```bash
# Enable for large files
export MULTIPART_DOWNLOAD=true
```

#### S3 Transfer Acceleration

```bash
# Enable transfer acceleration on buckets
aws s3api put-bucket-accelerate-configuration \
  --bucket cloudtrail-source-bucket \
  --accelerate-configuration Status=Enabled
```

### Configuration Caching

```bash
# Enable configuration caching
export CONFIG_CACHE_ENABLED=true
export CONFIG_REFRESH_INTERVAL=10m
```

## Security Best Practices

### Encryption

#### S3 Encryption

```bash
# Enable default encryption on buckets
aws s3api put-bucket-encryption \
  --bucket cloudtrail-output-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
      }
    }]
  }'
```

#### Lambda Environment Variables

```bash
# Use KMS key for environment variable encryption
aws lambda update-function-configuration \
  --function-name cloudtrail-log-parser \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

### Network Security

#### VPC Configuration

```bash
# Deploy Lambda in VPC for private access
aws lambda update-function-configuration \
  --function-name cloudtrail-log-parser \
  --vpc-config SubnetIds=subnet-12345,subnet-67890,SecurityGroupIds=sg-12345
```

#### VPC Endpoints

```bash
# Create S3 VPC endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-12345 \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids rtb-12345
```

### Access Control

#### Resource Policies

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:root"
    },
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:cloudtrail-log-parser",
    "Condition": {
      "ArnEquals": {
        "AWS:SourceArn": "arn:aws:sns:us-east-1:123456789012:cloudtrail-topic"
      }
    }
  }]
}
```

## Disaster Recovery

### Backup Strategy

#### Configuration Backup

```bash
# Automated S3 backup
aws s3 sync s3://config-bucket/cloudtrail-parser/ \
  s3://backup-bucket/cloudtrail-parser/$(date +%Y%m%d)/ \
  --storage-class GLACIER_IR
```

#### Lambda Function Backup

```bash
# Export function configuration
aws lambda get-function \
  --function-name cloudtrail-log-parser \
  --query 'Configuration' > lambda-config-backup.json

# Download function code
aws lambda get-function \
  --function-name cloudtrail-log-parser \
  --query 'Code.Location' --output text | \
  xargs wget -O lambda-code-backup.zip
```

### Multi-Region Deployment

```bash
# Deploy to multiple regions for resilience
for region in us-east-1 us-west-2 eu-west-1; do
  aws lambda create-function \
    --region $region \
    --function-name cloudtrail-log-parser \
    --runtime provided.al2 \
    --role arn:aws:iam::123456789012:role/cloudtrail-parser-role \
    --handler bootstrap \
    --zip-file fileb://lambda-deployment.zip
done
```

### Recovery Procedures

#### Full Recovery

```bash
#!/bin/bash
# recovery.sh

# Restore Lambda function
aws lambda create-function \
  --function-name cloudtrail-log-parser-recovered \
  --runtime provided.al2 \
  --role $LAMBDA_ROLE_ARN \
  --handler bootstrap \
  --zip-file fileb://lambda-code-backup.zip \
  --cli-input-json file://lambda-config-backup.json

# Restore configuration
aws s3 cp s3://backup-bucket/cloudtrail-parser/latest/rules.yaml \
  s3://config-bucket/cloudtrail-parser/rules.yaml

# Update SNS subscription
aws sns subscribe \
  --topic-arn $SNS_TOPIC_ARN \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:$REGION:$ACCOUNT:function:cloudtrail-log-parser-recovered
```

## Cost Optimization

### Cost Analysis

```python
# Calculate monthly costs
def calculate_monthly_cost(
    invocations_per_month,
    avg_duration_ms,
    memory_mb
):
    # Lambda pricing (us-east-1, ARM)
    request_cost = 0.0000002  # per request
    gb_second_cost = 0.0000133334  # per GB-second
    
    # Calculate GB-seconds
    gb_seconds = (memory_mb / 1024) * (avg_duration_ms / 1000) * invocations_per_month
    
    # Calculate costs
    request_charges = invocations_per_month * request_cost
    compute_charges = gb_seconds * gb_second_cost
    
    # Free tier (if applicable)
    free_requests = 1000000
    free_gb_seconds = 400000
    
    if invocations_per_month <= free_requests:
        request_charges = 0
    else:
        request_charges = (invocations_per_month - free_requests) * request_cost
    
    if gb_seconds <= free_gb_seconds:
        compute_charges = 0
    else:
        compute_charges = (gb_seconds - free_gb_seconds) * gb_second_cost
    
    return {
        'request_charges': request_charges,
        'compute_charges': compute_charges,
        'total': request_charges + compute_charges
    }
```

### Optimization Strategies

#### 1. Aggressive Filtering

```yaml
# Increase filter rate to reduce output size
rules:
  - name: "Aggressive Filter"
    matches:
      - field_name: "readOnly"
        regex: "^true$"
```

#### 2. Batch Processing

```bash
# Process multiple files in single invocation
export BATCH_SIZE=10
```

#### 3. Compression Optimization

```go
// Use maximum compression
gzipWriter.Reset(output)
gzipWriter.SetLevel(gzip.BestCompression)
```

#### 4. S3 Lifecycle Policies

```json
{
  "Rules": [{
    "Id": "TransitionToIA",
    "Status": "Enabled",
    "Transitions": [{
      "Days": 30,
      "StorageClass": "STANDARD_IA"
    }, {
      "Days": 90,
      "StorageClass": "GLACIER"
    }]
  }]
}
```

## Maintenance

### Regular Tasks

#### Weekly

- Review error logs
- Check filter effectiveness
- Monitor cost trends
- Update documentation

#### Monthly

- Review and update rules
- Performance analysis
- Security audit
- Cost optimization review

#### Quarterly

- Dependency updates
- Capacity planning
- DR testing
- Architecture review

### Update Procedures

#### Lambda Function Update

```bash
# Build new version
make build-lambda

# Update function code
aws lambda update-function-code \
  --function-name cloudtrail-log-parser \
  --zip-file fileb://lambda-deployment.zip

# Publish version
aws lambda publish-version \
  --function-name cloudtrail-log-parser \
  --description "Version $(git describe --tags)"

# Update alias after testing
aws lambda update-alias \
  --function-name cloudtrail-log-parser \
  --name production \
  --function-version $NEW_VERSION
```

#### Configuration Update

```bash
# Validate new configuration
go run cmd/config-export/main.go validate -f rules-new.yaml

# Test with dry run
go run cmd/config-export/main.go dryrun \
  -f rules-new.yaml \
  -e examples/cloudtrail.json

# Deploy configuration
aws s3 cp rules-new.yaml s3://config-bucket/cloudtrail-parser/rules.yaml

# Monitor metrics after deployment
aws cloudwatch get-metric-statistics \
  --namespace CloudTrailParser \
  --metric-name FilterRate \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average
```

### Troubleshooting Guide

#### Common Issues and Solutions

| Issue | Symptoms | Solution |
|-------|----------|----------|
| High memory usage | Lambda OOM errors | Increase memory, enable streaming |
| Slow processing | High duration metrics | Enable multipart download, optimize rules |
| Configuration not loading | Rules not applied | Check IAM permissions, validate config |
| S3 access denied | 403 errors in logs | Update bucket policy, check KMS keys |
| Low filter rate | < 30% events filtered | Review and update rules |
| Cold starts | High init duration | Enable provisioned concurrency |

## Conclusion

This deployment and operations guide provides comprehensive instructions for deploying, configuring, monitoring, and maintaining the CloudTrail Log Parser in production environments. Follow these best practices to ensure reliable, secure, and cost-effective operation of your log filtering infrastructure.