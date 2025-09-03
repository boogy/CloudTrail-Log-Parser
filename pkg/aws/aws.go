package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type Connection struct {
	sqs *sqs.Client
	sns *sns.Client

	queueURL string
	topicARN string
}

func New(awscfg *aws.Config, queueURL, topicARN string) (*Connection, error) {
	return &Connection{
		sqs:      sqs.NewFromConfig(*awscfg),
		sns:      sns.NewFromConfig(*awscfg),
		queueURL: queueURL,
		topicARN: topicARN,
	}, nil
}

func (c *Connection) SendSQSMessage(ctx context.Context, message string) error {
	if c.queueURL == "" {
		return fmt.Errorf("SQS queue URL is not configured")
	}
	
	_, err := c.sqs.SendMessage(ctx, &sqs.SendMessageInput{
		MessageBody: &message,
		QueueUrl:    &c.queueURL,
	})

	return err
}

func (c *Connection) PublishSNSMessage(ctx context.Context, message string) error {
	if c.topicARN == "" {
		return fmt.Errorf("SNS topic ARN is not configured")
	}
	
	_, err := c.sns.Publish(ctx, &sns.PublishInput{
		Message:  &message,
		TopicArn: &c.topicARN,
	})

	return err
}

func (c *Connection) BroadCastEvent(ctx context.Context, message string) error {
	if c.queueURL != "" {
		err := c.SendSQSMessage(ctx, message)
		if err != nil {
			return err
		}
	}

	if c.topicARN != "" {
		err := c.PublishSNSMessage(ctx, message)
		if err != nil {
			return err
		}
	}

	return nil
}
