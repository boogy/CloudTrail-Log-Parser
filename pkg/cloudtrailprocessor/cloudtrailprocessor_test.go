package cloudtrailprocessor_test

import (
	"context"
	ctp "ctlp/pkg/cloudtrailprocessor"
	"ctlp/pkg/rules"
	"ctlp/pkg/utils"
	"strings"
	"testing"

	"github.com/segmentio/encoding/json"
	"github.com/stretchr/testify/assert"
)

var (
	ctx        context.Context
	allRecords int
)

func readConfig(yamlConfig string) (*rules.Configuration, error) {
	rulesCfg, err := rules.Load(yamlConfig)
	if err != nil {
		return nil, err
	}
	return rulesCfg, nil
}

func readTestEvent() (*ctp.Cloudtrail, error) {
	// cloudtrail total records: 1679
	event := utils.ReadTestEvents("../../examples/cloudtrail.json")
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	inct := new(ctp.Cloudtrail)
	eventReader := strings.NewReader(string(eventJSON))
	decoder := json.NewDecoder(eventReader)
	err = decoder.Decode(inct)
	if err != nil {
		panic(err)
	}

	return inct, nil
}

func TestFilterRecords_1(t *testing.T) {
	assert := assert.New(t)
	ctx = context.Background()

	yamlConfig := `
version: 1.0.0
rules:
  - name: NotMatchingFilter
    matches:
    - field_name: eventSource
      regex: "ec2.*"
`
	matchingEc2Records := 73

	rulesCfg, err := readConfig(yamlConfig)
	assert.NoError(err)

	inct, err := readTestEvent()
	assert.NoError(err)

	allRecords = len(inct.Records)
	outRecord, err := ctp.FilterRecordsWithConfig(ctx, inct, rulesCfg)
	assert.NoError(err)
	assert.Equal(allRecords-matchingEc2Records, len(outRecord.Records))
}

func TestFilterRecords_2(t *testing.T) {
	assert := assert.New(t)
	ctx = context.Background()

	yamlConfig := `
version: 1.0.0
rules:
  - name: NotMatchingFilter
    matches:
    - field_name: eventSource
      regex: "kms.*"
`
	matchingKMSRecords := 1044

	rulesCfg, err := readConfig(yamlConfig)
	assert.NoError(err)

	inct, err := readTestEvent()
	assert.NoError(err)

	allRecords := len(inct.Records)
	outRecord, err := ctp.FilterRecordsWithConfig(ctx, inct, rulesCfg)
	assert.NoError(err)
	assert.Equal(allRecords-matchingKMSRecords, len(outRecord.Records))
}

func TestFilterRecords_4(t *testing.T) {
	assert := assert.New(t)
	ctx = context.Background()

	yamlConfig := `
version: 1.0.0
rules:
  - name: MatchingFilter
    matches:
    - field_name: eventSource
      regex: "^ssm.amazonaws.com$"
    - field_name: userIdentity.sessionContext.sessionIssuer.arn
      regex: "^arn:aws:iam::.*:role/demouser113$"
`
	rulesCfg, err := readConfig(yamlConfig)
	assert.NoError(err)

	inct, err := readTestEvent()
	assert.NoError(err)

	// Parse and return the filtered records
	outRecord, err := ctp.FilterRecordsWithConfig(ctx, inct, rulesCfg)

	assert.NoError(err)
	assert.Equal(1653, len(outRecord.Records))
}
