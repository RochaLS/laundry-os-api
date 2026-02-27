package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Server struct {
	ddb          *dynamodb.Client
	table        string
	sharedSecret string
}

type Stats struct {
	DeviceID   string  `json:"deviceId" dynamodbav:"deviceId"`
	TotalSpent float64 `json:"totalSpent" dynamodbav:"totalSpent"`
	NumRuns    int64   `json:"numRuns" dynamodbav:"numRuns"`
	Token      string  `json:"token,omitempty"`
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
		return resp(404, map[string]string{"error": "not found"})
	}

	stats := &Stats{DeviceID: deviceID}

	if v, ok := out.Item["totalSpent"].(*types.AttributeValueMemberN); ok {
		total, err := strconv.ParseFloat(v.Value, 64)
		stats.TotalSpent = total

		if err != nil {
			return resp(500, map[string]string{"error": "float conversion failed"})
		}

	}

	if v, ok := out.Item["numRuns"].(*types.AttributeValueMemberN); ok {
		total, err := strconv.ParseInt(v.Value, 10, 64)
		stats.NumRuns = total

		if err != nil {
			return resp(500, map[string]string{"error": "int conversion failed"})
		}
	}

	return resp(200, stats)

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
