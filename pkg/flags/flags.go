package flags

type S3Processor struct {
	CloudtrailOutputBucketName string
	ConfigFile                 string
	SNSPayloadType             string
	SQSPayloadType             string
	SNSTopicArn                string
	SQSQueueURL                string
	MultiPartDownload          bool
}
