package flags

import (
	"context"
)

type s3ProcType string

var S3ProcessorContextKey s3ProcType = "S3Processor"

func (c S3Processor) Inject(ctx context.Context) context.Context {
	return context.WithValue(ctx, S3ProcessorContextKey, c)
}

func GetConnectionFromContext(ctx context.Context) *S3Processor {
	c, _ := ctx.Value(S3ProcessorContextKey).(*S3Processor)
	return c
}
