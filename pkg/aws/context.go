package aws

import (
	"context"
	"fmt"
)

type AWSKeyType string

var awsKey AWSKeyType = "AWS"

func Inject(ctx context.Context, c *Connection) context.Context {
	return context.WithValue(ctx, awsKey, c)
}

func GetConnectionFromContext(ctx context.Context) (*Connection, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	
	val := ctx.Value(awsKey)
	if val == nil {
		return nil, fmt.Errorf("AWS connection not found in context")
	}
	
	c, ok := val.(*Connection)
	if !ok {
		return nil, fmt.Errorf("invalid AWS connection type in context")
	}
	
	return c, nil
}
