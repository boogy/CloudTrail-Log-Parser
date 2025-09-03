package cloudtrailprocessor

import (
	"bytes"
	"compress/gzip"
	"context"
	"ctlp/pkg/rules"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"runtime"
	"testing"
	"time"
)

// Benchmark test data generators
func generateCloudTrailRecords(count int) *Cloudtrail {
	ct := &Cloudtrail{
		Records: make([]json.RawMessage, count),
	}
	
	eventNames := []string{
		"CreateBucket", "DeleteBucket", "GetObject", "PutObject",
		"ListObjects", "CreateUser", "DeleteUser", "AssumeRole",
		"CreateAccessKey", "DeleteAccessKey", "StartInstances", "StopInstances",
	}
	
	eventSources := []string{
		"s3.amazonaws.com", "iam.amazonaws.com", "ec2.amazonaws.com",
		"rds.amazonaws.com", "lambda.amazonaws.com", "dynamodb.amazonaws.com",
	}
	
	regions := []string{
		"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1",
		"ap-northeast-1", "eu-central-1", "us-east-2", "ca-central-1",
	}
	
	for i := 0; i < count; i++ {
		record := map[string]interface{}{
			"eventID":            fmt.Sprintf("event-%d-%d", time.Now().Unix(), i),
			"eventName":          eventNames[rand.Intn(len(eventNames))],
			"eventSource":        eventSources[rand.Intn(len(eventSources))],
			"awsRegion":          regions[rand.Intn(len(regions))],
			"recipientAccountId": fmt.Sprintf("%012d", rand.Int63n(999999999999)),
			"eventTime":          time.Now().Format(time.RFC3339),
			"userIdentity": map[string]interface{}{
				"type":        "IAMUser",
				"principalId": fmt.Sprintf("AIDA%s", randString(16)),
				"arn":         fmt.Sprintf("arn:aws:iam::%012d:user/test-user-%d", rand.Int63n(999999999999), i),
			},
			"requestParameters": map[string]interface{}{
				"bucketName": fmt.Sprintf("test-bucket-%d", i),
				"key":        fmt.Sprintf("test-key-%d", i),
			},
		}
		
		data, _ := json.Marshal(record)
		ct.Records[i] = json.RawMessage(data)
	}
	
	return ct
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func generateTestRules() *rules.Configuration {
	return &rules.Configuration{
		Rules: []*rules.Rule{
			{
				Name: "drop-s3-read-operations",
				Matches: []*rules.Match{
					{FieldName: "eventSource", Regex: "s3\\.amazonaws\\.com"},
					{FieldName: "eventName", Regex: "(GetObject|ListObjects|HeadObject)"},
				},
			},
			{
				Name: "drop-describe-operations",
				Matches: []*rules.Match{
					{FieldName: "eventName", Regex: "^Describe.*"},
				},
			},
			{
				Name: "drop-specific-region",
				Matches: []*rules.Match{
					{FieldName: "awsRegion", Regex: "us-east-1"},
					{FieldName: "eventSource", Regex: "ec2\\.amazonaws\\.com"},
				},
			},
		},
	}
}

// Benchmarks for FilterRecords functions
// This benchmark creates configuration every time, simulating no cache reuse
func BenchmarkFilterRecords_WithoutCache_Small(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(100)
	cfg := generateTestRules()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// FilterRecordsWithConfig prepares the configuration every time internally
		_, _ = FilterRecordsWithConfig(ctx, ct, cfg)
	}
}

func BenchmarkFilterRecords_WithoutCache_Medium(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(1000)
	cfg := generateTestRules()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecordsWithConfig(ctx, ct, cfg)
	}
}

func BenchmarkFilterRecords_WithoutCache_Large(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(10000)
	cfg := generateTestRules()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecordsWithConfig(ctx, ct, cfg)
	}
}

// This benchmark reuses a prepared configuration, showing the benefit of caching
func BenchmarkFilterRecords_Cached_Small(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(100)
	cfg := generateTestRules()
	cachedCfg, _ := rules.PrepareConfiguration(cfg) // Prepare once, reuse many times
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecords(ctx, ct, cachedCfg)
	}
}

func BenchmarkFilterRecords_Cached_Medium(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(1000)
	cfg := generateTestRules()
	cachedCfg, _ := rules.PrepareConfiguration(cfg)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecords(ctx, ct, cachedCfg)
	}
}

func BenchmarkFilterRecords_Cached_Large(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(10000)
	cfg := generateTestRules()
	cachedCfg, _ := rules.PrepareConfiguration(cfg)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecords(ctx, ct, cachedCfg)
	}
}

// Benchmarks for JSON operations
func BenchmarkJSONDecode_Original(b *testing.B) {
	ct := generateCloudTrailRecords(1000)
	data, _ := json.Marshal(ct)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_ = jsonCloudTrailDecoder(reader)
	}
}

func BenchmarkJSONDecode_Current(b *testing.B) {
	ct := generateCloudTrailRecords(1000)
	data, _ := json.Marshal(ct)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_, _ = decodeJSON(reader)
	}
}

// Benchmarks for compression
func BenchmarkGzipWrite_Original(b *testing.B) {
	ct := generateCloudTrailRecords(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		encoder := json.NewEncoder(gw)
		_ = encoder.Encode(ct)
		_ = gw.Close()
	}
}

func BenchmarkGzipWrite_WithPool(b *testing.B) {
	ct := generateCloudTrailRecords(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		gw := gzipWriterPool.Get().(*gzip.Writer)
		gw.Reset(&buf)
		encoder := json.NewEncoder(gw)
		_ = encoder.Encode(ct)
		_ = gw.Close()
		gzipWriterPool.Put(gw)
	}
}

// Benchmarks for regex compilation and matching
func BenchmarkRegexCompilation_NoCache(b *testing.B) {
	patterns := []string{
		"s3\\.amazonaws\\.com",
		"(GetObject|ListObjects|HeadObject)",
		"^Describe.*",
		"us-east-1",
		"ec2\\.amazonaws\\.com",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		for _, pattern := range patterns {
			re, _ := regexp.Compile(pattern)
			_ = re.MatchString("s3.amazonaws.com")
		}
	}
}

func BenchmarkRegexCompilation_WithCache(b *testing.B) {
	patterns := []string{
		"s3\\.amazonaws\\.com",
		"(GetObject|ListObjects|HeadObject)",
		"^Describe.*",
		"us-east-1",
		"ec2\\.amazonaws\\.com",
	}
	
	// Using a simple cache implementation for benchmark
	cache := make(map[string]*regexp.Regexp)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		for _, pattern := range patterns {
			re, ok := cache[pattern]
			if !ok {
				re, _ = regexp.Compile(pattern)
				cache[pattern] = re
			}
			_ = re.MatchString("s3.amazonaws.com")
		}
	}
}

// Parallel processing benchmarks
func BenchmarkParallelProcessing_Sequential(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(10000)
	cfg := generateTestRules()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		oldParallelism := runtime.GOMAXPROCS(1)
		_, _ = FilterRecordsWithConfig(ctx, ct, cfg)
		runtime.GOMAXPROCS(oldParallelism)
	}
}

func BenchmarkParallelProcessing_Parallel(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(10000)
	cfg := generateTestRules()
	cachedCfg, _ := rules.PrepareConfiguration(cfg)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = FilterRecords(ctx, ct, cachedCfg)
	}
}

// Memory allocation benchmarks
func BenchmarkMemoryAllocations_MapCreation_NoPool(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		m := make(map[string]interface{})
		m["test"] = "value"
		m["test2"] = 123
		m["test3"] = true
	}
}

func BenchmarkMemoryAllocations_MapCreation_WithPool(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		m := recordMapPool.Get().(map[string]interface{})
		m["test"] = "value"
		m["test2"] = 123
		m["test3"] = true
		
		// Clear and return to pool
		for k := range m {
			delete(m, k)
		}
		recordMapPool.Put(m)
	}
}

// Integration benchmark
func BenchmarkFullPipeline_Original(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(5000)
	data, _ := json.Marshal(ct)
	
	// Compress data
	var compressedBuf bytes.Buffer
	gw := gzip.NewWriter(&compressedBuf)
	_, _ = gw.Write(data)
	_ = gw.Close()
	
	cfg := generateTestRules()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Decompress
		gr, _ := gzip.NewReader(bytes.NewReader(compressedBuf.Bytes()))
		decodedCT := jsonCloudTrailDecoder(gr)
		_ = gr.Close()
		
		// Filter
		filteredCT, _ := FilterRecordsWithConfig(ctx, decodedCT, cfg)
		
		// Re-compress
		var outBuf bytes.Buffer
		gwo := gzip.NewWriter(&outBuf)
		encoder := json.NewEncoder(gwo)
		_ = encoder.Encode(filteredCT)
		_ = gwo.Close()
	}
}

func BenchmarkFullPipeline_Current(b *testing.B) {
	ctx := context.Background()
	ct := generateCloudTrailRecords(5000)
	data, _ := json.Marshal(ct)
	
	// Compress data
	var compressedBuf bytes.Buffer
	gw := gzip.NewWriter(&compressedBuf)
	_, _ = gw.Write(data)
	_ = gw.Close()
	
	cfg := generateTestRules()
	cachedCfg, _ := rules.PrepareConfiguration(cfg)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Decompress
		gr, _ := gzip.NewReader(bytes.NewReader(compressedBuf.Bytes()))
		decodedCT, _ := decodeJSON(gr)
		_ = gr.Close()
		
		// Filter
		filteredCT, _ := FilterRecords(ctx, decodedCT, cachedCfg)
		
		// Re-compress with pool
		var outBuf bytes.Buffer
		gwo := gzipWriterPool.Get().(*gzip.Writer)
		gwo.Reset(&outBuf)
		encoder := json.NewEncoder(gwo)
		_ = encoder.Encode(filteredCT)
		_ = gwo.Close()
		gzipWriterPool.Put(gwo)
	}
}