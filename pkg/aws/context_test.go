package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConnectionFromContext_NilContext(t *testing.T) {
	conn, err := GetConnectionFromContext(nil)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "context is nil")
}

func TestGetConnectionFromContext_NoConnection(t *testing.T) {
	ctx := context.Background()
	conn, err := GetConnectionFromContext(ctx)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "AWS connection not found in context")
}

func TestGetConnectionFromContext_ValidConnection(t *testing.T) {
	ctx := context.Background()
	expectedConn := &Connection{
		queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
		topicARN: "arn:aws:sns:us-east-1:123456789012:test-topic",
	}
	
	ctx = Inject(ctx, expectedConn)
	
	conn, err := GetConnectionFromContext(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, expectedConn, conn)
}

func TestGetConnectionFromContext_WrongType(t *testing.T) {
	ctx := context.Background()
	// Inject wrong type
	ctx = context.WithValue(ctx, awsKey, "not a connection")
	
	conn, err := GetConnectionFromContext(ctx)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "invalid AWS connection type in context")
}