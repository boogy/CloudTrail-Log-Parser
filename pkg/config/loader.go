package config

import (
	"context"
	"ctlp/pkg/rules"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
)

// ConfigLoader defines the interface for loading configuration
type ConfigLoader interface {
	Load(ctx context.Context) (*rules.Configuration, error)
	String() string // For logging purposes
}

// S3API interface for S3 operations
type S3API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// SSMAPI interface for SSM Parameter Store operations
type SSMAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// SecretsManagerAPI interface for Secrets Manager operations
type SecretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// S3ConfigLoader loads configuration from S3
type S3ConfigLoader struct {
	bucket string
	key    string
	client S3API
}

// NewS3ConfigLoader creates a new S3 configuration loader
func NewS3ConfigLoader(bucket, key string, client S3API) *S3ConfigLoader {
	return &S3ConfigLoader{
		bucket: bucket,
		key:    key,
		client: client,
	}
}

// Load loads configuration from S3
func (l *S3ConfigLoader) Load(ctx context.Context) (*rules.Configuration, error) {
	log.Ctx(ctx).Debug().
		Str("bucket", l.bucket).
		Str("key", l.key).
		Msg("loading configuration from S3")

	resp, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(l.key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object: %w", err)
	}

	cfg, err := rules.Load(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (l *S3ConfigLoader) String() string {
	return fmt.Sprintf("S3ConfigLoader(bucket=%s, key=%s)", l.bucket, l.key)
}

// SSMConfigLoader loads configuration from SSM Parameter Store
type SSMConfigLoader struct {
	parameterName string
	client        SSMAPI
}

// NewSSMConfigLoader creates a new SSM Parameter Store configuration loader
func NewSSMConfigLoader(parameterName string, client SSMAPI) *SSMConfigLoader {
	return &SSMConfigLoader{
		parameterName: parameterName,
		client:        client,
	}
}

// Load loads configuration from SSM Parameter Store
func (l *SSMConfigLoader) Load(ctx context.Context) (*rules.Configuration, error) {
	log.Ctx(ctx).Debug().
		Str("parameter", l.parameterName).
		Msg("loading configuration from SSM Parameter Store")

	resp, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(l.parameterName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get SSM parameter: %w", err)
	}

	if resp.Parameter == nil || resp.Parameter.Value == nil {
		return nil, fmt.Errorf("SSM parameter value is nil")
	}

	cfg, err := rules.Load(*resp.Parameter.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (l *SSMConfigLoader) String() string {
	return fmt.Sprintf("SSMConfigLoader(parameter=%s)", l.parameterName)
}

// SecretsManagerConfigLoader loads configuration from AWS Secrets Manager
type SecretsManagerConfigLoader struct {
	secretID string
	client   SecretsManagerAPI
}

// NewSecretsManagerConfigLoader creates a new Secrets Manager configuration loader
func NewSecretsManagerConfigLoader(secretID string, client SecretsManagerAPI) *SecretsManagerConfigLoader {
	return &SecretsManagerConfigLoader{
		secretID: secretID,
		client:   client,
	}
}

// Load loads configuration from Secrets Manager
func (l *SecretsManagerConfigLoader) Load(ctx context.Context) (*rules.Configuration, error) {
	log.Ctx(ctx).Debug().
		Str("secretId", l.secretID).
		Msg("loading configuration from Secrets Manager")

	resp, err := l.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(l.secretID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret value: %w", err)
	}

	if resp.SecretString == nil {
		return nil, fmt.Errorf("secret string is nil")
	}

	cfg, err := rules.Load(*resp.SecretString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (l *SecretsManagerConfigLoader) String() string {
	return fmt.Sprintf("SecretsManagerConfigLoader(secretId=%s)", l.secretID)
}

// LocalConfigLoader loads configuration from local file
type LocalConfigLoader struct {
	path string
}

// NewLocalConfigLoader creates a new local file configuration loader
func NewLocalConfigLoader(path string) *LocalConfigLoader {
	return &LocalConfigLoader{
		path: path,
	}
}

// Load loads configuration from local file
func (l *LocalConfigLoader) Load(ctx context.Context) (*rules.Configuration, error) {
	log.Ctx(ctx).Debug().
		Str("path", l.path).
		Msg("loading configuration from local file")

	return rules.LoadFromConfigFile(ctx, l.path)
}

func (l *LocalConfigLoader) String() string {
	return fmt.Sprintf("LocalConfigLoader(path=%s)", l.path)
}

// CachedConfigLoader wraps another loader with caching functionality
type CachedConfigLoader struct {
	loader      ConfigLoader
	ttl         time.Duration
	mu          sync.RWMutex
	lastLoaded  time.Time
	config      *rules.Configuration
	cachedRules *rules.CachedConfiguration
}

// NewCachedConfigLoader creates a new cached configuration loader
func NewCachedConfigLoader(loader ConfigLoader, ttl time.Duration) *CachedConfigLoader {
	return &CachedConfigLoader{
		loader: loader,
		ttl:    ttl,
	}
}

// Load loads configuration with caching
func (l *CachedConfigLoader) Load(ctx context.Context) (*rules.Configuration, error) {
	l.mu.RLock()
	if l.config != nil && time.Since(l.lastLoaded) < l.ttl {
		config := l.config
		l.mu.RUnlock()
		log.Ctx(ctx).Debug().
			Str("loader", l.loader.String()).
			Dur("age", time.Since(l.lastLoaded)).
			Msg("returning cached configuration")
		return config, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock
	if l.config != nil && time.Since(l.lastLoaded) < l.ttl {
		return l.config, nil
	}

	log.Ctx(ctx).Debug().
		Str("loader", l.loader.String()).
		Msg("loading fresh configuration")

	config, err := l.loader.Load(ctx)
	if err != nil {
		return nil, err
	}

	// Pre-compile the rules for better performance
	cachedRules, err := rules.PrepareConfiguration(config)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare cached rules: %w", err)
	}

	l.config = config
	l.cachedRules = cachedRules
	l.lastLoaded = time.Now()

	return config, nil
}

// LoadCached returns the cached compiled rules for better performance
func (l *CachedConfigLoader) LoadCached(ctx context.Context) (*rules.CachedConfiguration, error) {
	_, err := l.Load(ctx) // Ensure config is loaded
	if err != nil {
		return nil, err
	}

	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cachedRules, nil
}

func (l *CachedConfigLoader) String() string {
	return fmt.Sprintf("CachedConfigLoader(loader=%s, ttl=%s)", l.loader.String(), l.ttl)
}

// CreateLoaderFromEnv creates a configuration loader based on environment variables
func CreateLoaderFromEnv(awsConfig *aws.Config) ConfigLoader {
	configSource := getEnv("CONFIG_SOURCE", "local")

	var baseLoader ConfigLoader

	switch strings.ToLower(configSource) {
	case "s3":
		bucket := getEnv("CONFIG_S3_BUCKET", "")
		key := getEnv("CONFIG_S3_KEY", "")
		if bucket == "" || key == "" {
			if s3Path := getEnv("CONFIG_S3_PATH", ""); s3Path != "" {
				parts := strings.SplitN(s3Path, "/", 2)
				if len(parts) == 2 {
					bucket = parts[0]
					key = parts[1]
				}
			}
		}
		if bucket != "" && key != "" {
			s3Client := s3.NewFromConfig(*awsConfig)
			baseLoader = NewS3ConfigLoader(bucket, key, s3Client)
		}

	case "ssm":
		paramName := getEnv("CONFIG_SSM_PARAMETER", "")
		if paramName != "" {
			ssmClient := ssm.NewFromConfig(*awsConfig)
			baseLoader = NewSSMConfigLoader(paramName, ssmClient)
		}

	case "secretsmanager":
		secretID := getEnv("CONFIG_SECRET_ID", "")
		if secretID != "" {
			smClient := secretsmanager.NewFromConfig(*awsConfig)
			baseLoader = NewSecretsManagerConfigLoader(secretID, smClient)
		}

	case "local":
		fallthrough
	default:
		configFile := getEnv("CONFIG_FILE", "./rules.yaml")
		baseLoader = NewLocalConfigLoader(configFile)
	}

	// Wrap with caching if enabled
	if getEnv("CONFIG_CACHE_ENABLED", "true") == "true" {
		ttlStr := getEnv("CONFIG_REFRESH_INTERVAL", "5m")
		ttl, err := time.ParseDuration(ttlStr)
		if err != nil {
			ttl = 5 * time.Minute
		}
		return NewCachedConfigLoader(baseLoader, ttl)
	}

	return baseLoader
}

func getEnv(key, defaultVal string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return defaultVal
}
