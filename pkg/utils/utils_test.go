package utils_test

import (
	"ctlp/pkg/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainsString(t *testing.T) {
	assert := assert.New(t)

	slice := []string{"a", "b", "c"}
	assert.True(utils.ContainsString(slice, "a"))
	assert.False(utils.ContainsString(slice, "d"))

	slice2 := []string{"nexthink", "is", "1337"}
	assert.True(utils.ContainsString(slice2, "nexthink"))
	assert.False(utils.ContainsString(slice2, "1338"))
}

func TestIsFieldPresent(t *testing.T) {
	assert := assert.New(t)

	event := map[string]interface{}{
		"foo": "bar",
		"baz": map[string]interface{}{
			"qux": "quux",
		},
	}
	sTrue, sTrueValue := utils.IsFieldPresent("baz.qux", event)
	assert.True(sTrue)
	assert.Equal("quux", sTrueValue)
}

func TestFieldExists(t *testing.T) {
	assert := assert.New(t)
	event := map[string]interface{}{
		"foo": "bar",
		"baz": map[string]interface{}{
			"qux": "quux",
			"quuux": map[string]interface{}{
				"quuz": "quuuxa",
			},
		},
	}

	fooBar, fooBarValue := utils.FieldExists("foo", event)
	assert.True(fooBar, "fooBar must be true")
	assert.Equal("bar", fooBarValue, "foo value must be bar")

	bazQuux, bazQuuxValue := utils.FieldExists("baz.qux", event)
	assert.True(bazQuux)
	assert.Equal("quux", bazQuuxValue)

	bazQuuux, bazQuuuxValue := utils.FieldExists("baz.quuux.quuz", event)
	assert.True(bazQuuux)
	assert.Equal("quuuxa", bazQuuuxValue)
}

func TestExtractStringField(t *testing.T) {
	assert := assert.New(t)
	event := map[string]interface{}{
		"foo": "bar",
	}

	foo := utils.ExtractStringField(event, "foo")
	assert.IsType("string", foo, "foo must be a string")
	assert.Equal("bar", foo, "foo value must be bar")
}

func TestComplexInlineEvent(t *testing.T) {
	assert := assert.New(t)
	event := map[string]interface{}{
		"userIdentity": map[string]interface{}{
			"type":      "AWSService",
			"invokedBy": "lambda.amazonaws.com",
		},
		"eventTime":       "2024-03-13T08:33:21Z",
		"eventSource":     "sts.amazonaws.com",
		"eventName":       "AssumeRole",
		"awsRegion":       "eu-west-3",
		"sourceIPAddress": "lambda.amazonaws.com",
		"userAgent":       "lambda.amazonaws.com",
		"requestParameters": map[string]interface{}{
			"roleArn":         "arn:aws:iam::123456789012:role/some-role-name",
			"roleSessionName": "some-session-name",
		},
		"responseElements": map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":  "ASIA44BIUFMKVYOQXHVY",
				"sessionToken": "[redacted]",
				"expiration":   "Mar 13, 2024, 8:33:21 PM",
			},
		},
		"requestID":          "6e62536c-6013-4435-8efc-c8a9d6e7cae6",
		"eventID":            "f95ed4ce-7a83-319c-9f7c-95c9b9d8cef2",
		"readOnly":           true,
		"eventType":          "AwsApiCall",
		"managementEvent":    true,
		"recipientAccountId": "123456789012",
		"sharedEventID":      "4b22c4c9-d1ee-49da-b2d4-c9080af89503",
		"eventCategory":      "Management",
	}
	arnExists, arnValue := utils.FieldExists("userIdentity.sessionContext.sessionIssuer.arn", event)
	assert.False(arnExists)
	assert.Equal(nil, arnValue)

	keyExists, keyValue := utils.FieldExists("responseElements.credentials.accessKeyId", event)
	assert.True(keyExists)
	assert.Equal("ASIA44BIUFMKVYOQXHVY", keyValue)

	mfaAuthExists, mfaAuthValue := utils.FieldExists("userIdentity.sessionContext.attributes.mfaAuthenticated", event)
	assert.False(mfaAuthExists)
	assert.Nil(mfaAuthValue)

	eventIdExists, eventIdValue := utils.FieldExists("eventID", event)
	assert.True(eventIdExists)
	assert.Equal("f95ed4ce-7a83-319c-9f7c-95c9b9d8cef2", eventIdValue)
}
