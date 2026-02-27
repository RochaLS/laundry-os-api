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
	var stats Stats
	if err := json.Unmarshal([]byte(req.Body), &stats); err != nil {
		return resp(400, map[string]string{"error": "invalid json"})
	}

	stats.DeviceID = strings.TrimSpace(stats.DeviceID)

	if stats.Token == "" || s.sharedSecret == "" || !timingSafeEq(stats.Token, s.sharedSecret) {
		return resp(401, map[string]string{"error": "unauthorized"})
	}

	if stats.DeviceID == "" {
		return resp(400, map[string]string{"error": "deviceId required"})
	}

	totalSpentStr := strconv.FormatFloat(stats.TotalSpent, 'f', 2, 64)
	numRunsStr := strconv.FormatInt(stats.NumRuns, 10)
	updatedAtStr := strconv.FormatInt(time.Now().UnixMilli(), 10)

	_, err := s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item: map[string]types.AttributeValue{
			"deviceId":   &types.AttributeValueMemberS{Value: stats.DeviceID},
			"totalSpent": &types.AttributeValueMemberN{Value: totalSpentStr},
			"numRuns":    &types.AttributeValueMemberN{Value: numRunsStr},
			"updatedAt":  &types.AttributeValueMemberN{Value: updatedAtStr},
		},
	})

	if err != nil {
		return resp(500, map[string]string{
			"error": err.Error(),
			"table": s.table,
		})
	}

	return resp(200, map[string]any{"ok": true, "lastUpdatedAt": updatedAtStr})

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
