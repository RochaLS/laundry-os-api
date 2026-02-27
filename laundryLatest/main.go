package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Command struct {
	DeviceID        string `json:"deviceId"`
	Type            string `json:"type"`
	DurationMinutes int    `json:"durationMinutes"`
	CreatedAt       int64  `json:"createdAt"`
}

type LatestResponse struct {
	Command *Command `json:"command"`
}

type Server struct {
	ddb          *dynamodb.Client
	table        string
	sharedSecret string
}

func timingSafeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func resp(status int, v any) (events.APIGatewayProxyResponse, error) {
	b, _ := json.Marshal(v)
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type":                "application/json",
			"Access-Control-Allow-Origin": "*",
		},
		Body: string(b),
	}, nil
}

func (s *Server) handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	deviceID := strings.TrimSpace(req.QueryStringParameters["deviceId"])
	token := req.QueryStringParameters["token"]

	if deviceID == "" {
		return resp(400, map[string]string{"error": "deviceId required"})
	}
	if token == "" || s.sharedSecret == "" || !timingSafeEq(token, s.sharedSecret) {
		return resp(401, map[string]string{"error": "unauthorized"})
	}

	out, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"deviceId": &types.AttributeValueMemberS{Value: deviceID},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return resp(500, map[string]string{"error": "get failed"})
	}
	if out.Item == nil {
		return resp(200, LatestResponse{Command: nil})
	}

	// if servedAt exists, return null (serve-once)
	if _, ok := out.Item["servedAt"]; ok {
		return resp(200, LatestResponse{Command: nil})
	}

	cmd := &Command{DeviceID: deviceID}

	if v, ok := out.Item["type"].(*types.AttributeValueMemberS); ok {
		cmd.Type = v.Value
	}
	if v, ok := out.Item["durationMinutes"].(*types.AttributeValueMemberN); ok {
		cmd.DurationMinutes = int(mustInt64(v.Value))
	}
	if v, ok := out.Item["createdAt"].(*types.AttributeValueMemberN); ok {
		cmd.CreatedAt = mustInt64(v.Value)
	}

	// mark served
	now := time.Now().UnixMilli()
	_, _ = s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"deviceId": &types.AttributeValueMemberS{Value: deviceID},
		},
		UpdateExpression: aws.String("SET servedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)},
		},
	})

	return resp(200, LatestResponse{Command: cmd})
}

func mustInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

func main() {
	cfg, _ := config.LoadDefaultConfig(context.Background())
	s := &Server{
		ddb:          dynamodb.NewFromConfig(cfg),
		table:        os.Getenv("TABLE_NAME"),
		sharedSecret: os.Getenv("SHARED_SECRET"),
	}
	lambda.Start(s.handler)
}
