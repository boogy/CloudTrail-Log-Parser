package rules_test

import (
	"context"
	"ctlp/pkg/rules"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	ctx       context.Context
	testEvent = map[string]any{
		"eventID":            "b87bff27-86e9-4bfd-823f-172893b353fb",
		"requestID":          "f8ca9850-87ea-47ff-ae2d-b59ef1117599",
		"eventName":          "AssumeRole",
		"eventTime":          "2021-08-25T20:00:00Z",
		"eventSource":        "sts.amazonaws.com",
		"awsRegion":          "us-west-2",
		"recipientAccountId": "123456789012",
		"userIdentity": map[string]any{
			"accessKeyId":  "ASIAWCP5BTEJF6KKU6TO",
			"accountId":    "123456789012",
			"arn":          "arn:aws:sts::123456789012:assumed-role/cloudquery-ro/cloudquery",
			"assumed_role": "cloudquery-ro",
			"principalId":  "AROAWCP5BTEJGU4T4PXYE:cloudquery",
			"session_name": "cloudquery",
			"sessionContext": map[string]any{
				"attributes": map[string]any{
					"creationDate":     "2021-08-25T20:00:00Z",
					"mfaAuthenticated": "false",
				},
				"sessionIssuer": map[string]any{
					"accountId":   "123456789012",
					"arn":         "arn:aws:iam::123456789012:role/cloudquery",
					"principalId": "AROAWCP5BTEJGU1T0PXYE",
					"type":        "Role",
					"userName":    "cloudquery",
				},
			},
		},
		"sharedEventID": "7c2ea921-b8b3-48ad-b49f-1890b80ad175",
	}
	yamlConfig = `
version: 1.0.0
rules:
  - name: check_kms
    matches:
    - field_name: eventName
      regex: ".*crypt"
    - field_name: eventSource
      regex: "kms.*"
  - name: check_complex
    matches:
    - field_name: eventName
      regex: "AssumeRole$"
    - field_name: userIdentity.sessionContext.sessionIssuer.arn
      regex: "arn:aws:iam::.*:role/cloudquery.*"
  - name: check only 2 matches - this event should not match
    matches:
    - field_name: eventName
      regex: "^AssumeRole$"
    - field_name: eventSource
      regex: "sts.amazonaws.com"
    - field_name: userIdentity.sessionContext.sessionIssuer.does-not-exist
      regex: "arn:aws:iam::.*:user/cloudquery.*"
`
)

func TestLoadFromConfigFile(t *testing.T) {
	assert := assert.New(t)

	rulesCfg, err := rules.LoadFromConfigFile(ctx, "../../rules-example.yaml")
	assert.Nil(err)

	err = rulesCfg.Validate()
	assert.Nil(err)
}

func TestEvalRules(t *testing.T) {
	assert := assert.New(t)

	ctr, err := rules.Load(yamlConfig)
	assert.Nil(err)

	err = ctr.Validate()
	assert.Nil(err)

	// Event must match the rule
	match, droped, err := ctr.Rules[0].Eval(map[string]any{
		"eventName":   "Encrypt",
		"eventSource": "kms.amazonaws.com",
	})

	fmt.Println(match, droped.RuleName, err)

	assert.NoError(err)
	assert.True(match)
	assert.Equal("check_kms", droped.RuleName)

	// Event does not match the rule
	match2, droped2, err := ctr.Rules[0].Eval(map[string]any{
		"eventName":   "Encrypt",
		"eventSource": "logs.amazonaws.com",
	})
	assert.Nil(err)
	assert.False(match2)
	assert.NotEqual(t, nil, droped2.RuleName)
}

func TestEvalRuleComplexField(t *testing.T) {
	assert := assert.New(t)
	ctr, _ := rules.Load(yamlConfig)

	// Event must match the rule (Rule[1] == check_complex)
	match, droped, err := ctr.Rules[1].Eval(testEvent)
	assert.Nil(err)
	assert.True(match)
	assert.Equal("check_complex", droped.RuleName)

	// Event does not match the rule
	match2, dropedEvent, err := ctr.Rules[1].Eval(map[string]any{
		"userIdentity": map[string]any{
			"sessionContext": map[string]any{
				"sessionIssuer": map[string]any{
					"accountId": "123456789012",
					"arn":       "arn:aws:iam::123456789012:role/not-the-user-youre-looking-for-cloudquery",
				},
			},
		},
	})
	assert.Nil(err)
	assert.False(match2)
	assert.Equal("", dropedEvent.RuleName)
}

func TestEvalRuleWith1NoMatch(t *testing.T) {
	assert := assert.New(t)

	ctr, _ := rules.Load(yamlConfig)
	match, droped, err := ctr.Rules[2].Eval(testEvent)
	assert.Nil(err)
	// event must not match as the third check is not present in the event
	assert.False(match)

	// Event is dropped rule name must be empty
	assert.Equal("", droped.RuleName)
}
