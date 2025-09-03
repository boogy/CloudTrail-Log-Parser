//go:build dev
// +build dev

package main

import (
	"compress/gzip"
	"context"
	"ctlp/pkg/cloudtrailprocessor"
	"ctlp/pkg/rules"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	ctx               context.Context
	allExamples       *bool
	outputRecords     *bool
	allExamplesFolder string
	testFileName      string
	rulesTestFile     string
	outputFolder      string
)

func init() {
	logLevelStr := os.Getenv("LOG_LEVEL")

	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.InfoLevel // Default to Info level
	}

	// UNIX Time is faster and smaller than most timestamps
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix // time.RFC3339 // zerolog.TimeFormatUnix
	zerolog.TimestampFunc = func() time.Time { return time.Now().In(time.UTC) }
	zerolog.SetGlobalLevel(logLevel)
	zerolog.ErrorFieldName = "error"
	zerolog.MessageFieldName = "msg"

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	ctx = context.Background()
	ctx = logger.WithContext(ctx)

	allExamples = flag.Bool("all", false, "Run all examples")
	outputRecords = flag.Bool("output", true, "Output filtered records to out_test folder")
	flag.StringVar(&allExamplesFolder, "folder", "./examples", "Folder for multiple example files")
	flag.StringVar(&rulesTestFile, "rules", "./rules-test.yaml", "Rules test yaml file")
	flag.StringVar(&testFileName, "file", "./examples/cloudtrail.json", "Test file")
	flag.StringVar(&outputFolder, "out", "./out_test", "Output folder for filtered logs")
	flag.Parse()

	// Create output folder if it doesn't exist
	if *outputRecords {
		if err := os.MkdirAll(outputFolder, 0755); err != nil {
			log.Error().Err(err).Msg("failed to create output folder")
		}
	}
}

func Handler(ctx context.Context, cloudtrailData *cloudtrailprocessor.Cloudtrail, fileName string) error {
	start := time.Now()

	// Load configuration
	rulesCfg, err := rules.LoadFromConfigFile(ctx, rulesTestFile)
	if err != nil {
		return fmt.Errorf("failed to load rules from file %s: %w", rulesTestFile, err)
	}
	err = rulesCfg.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate rules from file %s: %w", rulesTestFile, err)
	}

	// Prepare the configuration with compiled regexes
	cachedCfg, err := rules.PrepareConfiguration(rulesCfg)
	if err != nil {
		return fmt.Errorf("failed to prepare rules configuration: %w", err)
	}

	// Filter records using the cached configuration
	outRecord, err := cloudtrailprocessor.FilterRecords(ctx, cloudtrailData, cachedCfg)
	if err != nil {
		return fmt.Errorf("failed to filter records: %w", err)
	}

	// print summary of results
	log.Warn().
		Int("input", len(cloudtrailData.Records)).
		Int("output", len(outRecord.Records)).
		Int("dropped", len(cloudtrailData.Records)-len(outRecord.Records)).
		Str("exeTime", fmt.Sprint(time.Since(start))).
		Str("fileName", fileName).
		Msg("completed")

	if *outputRecords {
		// Extract base filename without path
		baseName := fileName
		if idx := strings.LastIndex(fileName, "/"); idx >= 0 {
			baseName = fileName[idx+1:]
		}
		// Remove .json extension if present
		if strings.HasSuffix(baseName, ".json") {
			baseName = baseName[:len(baseName)-5]
		}
		if strings.HasSuffix(baseName, ".json.gz") {
			baseName = baseName[:len(baseName)-8]
		}
		outputPath := fmt.Sprintf("%s/%s_filtered.json", outputFolder, baseName)
		WriteJsonToFile(outputPath, outRecord)
		log.Info().Str("output", outputPath).Msg("wrote filtered logs")
	}

	return nil
}

func main() {
	start := time.Now()
	
	if *allExamples {
		files, err := os.ReadDir(allExamplesFolder)
		if err != nil {
			log.Fatal().Err(err).Msg(fmt.Sprintf("failed to read directory: %s", allExamplesFolder))
		}

		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".json") && !strings.HasSuffix(file.Name(), ".json.gz") {
				continue // Skip non-JSON files
			}
			
			fileName := fmt.Sprintf("%s/%s", allExamplesFolder, file.Name())
			log.Info().Str("file", fileName).Msg("processing file")
			
			cloudtrailData, err := LoadCloudTrailFile(fileName)
			if err != nil {
				log.Error().Err(err).Str("file", fileName).Msg("failed to load CloudTrail file")
				continue
			}
			
			if err := Handler(ctx, cloudtrailData, fileName); err != nil {
				log.Error().Err(err).Str("file", fileName).Msg("failed to process file")
			}
		}
	} else {
		log.Info().Str("file", testFileName).Msg("processing single file")
		
		cloudtrailData, err := LoadCloudTrailFile(testFileName)
		if err != nil {
			log.Fatal().Err(err).Str("file", testFileName).Msg("failed to load CloudTrail file")
		}
		
		if err := Handler(ctx, cloudtrailData, testFileName); err != nil {
			log.Fatal().Err(err).Str("file", testFileName).Msg("failed to process file")
		}
	}

	fmt.Printf("\nExecution time: %s\n", time.Since(start))
	fmt.Printf("Output folder: %s\n", outputFolder)
}

// LoadCloudTrailFile loads a CloudTrail JSON file (supports .json and .json.gz)
func LoadCloudTrailFile(filePath string) (*cloudtrailprocessor.Cloudtrail, error) {
	var rawData []byte
	var err error

	if strings.HasSuffix(filePath, ".gz") {
		// Handle gzipped file
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()

		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()

		rawData, err = io.ReadAll(gzReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read gzipped data: %w", err)
		}
	} else {
		// Handle regular JSON file
		rawData, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
	}

	// Parse the CloudTrail JSON
	var cloudtrailData cloudtrailprocessor.Cloudtrail
	err = json.Unmarshal(rawData, &cloudtrailData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CloudTrail JSON: %w", err)
	}

	return &cloudtrailData, nil
}

func WriteJsonToFile(fileName string, data *cloudtrailprocessor.Cloudtrail) {
	file, err := os.Create(fileName)
	if err != nil {
		log.Error().Err(err).Str("file", fileName).Msg("failed to create file")
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(data)
	if err != nil {
		log.Error().Err(err).Str("file", fileName).Msg("failed to encode data")
	}
}
