package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendSQSMessage_EmptyQueueURL(t *testing.T) {
	conn := &Connection{
		queueURL: "",
	}

	err := conn.SendSQSMessage(context.Background(), "test message")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SQS queue URL is not configured")
}

func TestPublishSNSMessage_EmptyTopicARN(t *testing.T) {
	conn := &Connection{
		topicARN: "",
	}

	err := conn.PublishSNSMessage(context.Background(), "test message")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SNS topic ARN is not configured")
}

func TestBroadCastEvent_EmptyConfiguration(t *testing.T) {
	conn := &Connection{
		queueURL: "",
		topicARN: "",
	}

	// Should not error when both are empty (no-op)
	err := conn.BroadCastEvent(context.Background(), "test message")
	assert.NoError(t, err)
}
