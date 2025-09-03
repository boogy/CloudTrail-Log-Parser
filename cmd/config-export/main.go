package main

import (
	"ctlp/pkg/rules"
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		inputFile  = flag.String("input", "rules-example.yaml", "Input YAML configuration file")
		outputFile = flag.String("output", "", "Output file (if empty, prints to stdout)")
		format     = flag.String("format", "json", "Output format: json or yaml")
	)
	flag.Parse()

	// Read the input file
	rawCfg, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
	}

	// Load the versioned configuration
	cfg, err := rules.LoadVersioned(string(rawCfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Export to the desired format
	output, err := cfg.Export(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting configuration: %v\n", err)
		os.Exit(1)
	}

	// Write output
	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Configuration exported to %s\n", *outputFile)
	} else {
		fmt.Print(string(output))
	}
}