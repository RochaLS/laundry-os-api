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
	Token           string `json:"token,omitempty"`
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
	var cmd Command
	if err := json.Unmarshal([]byte(req.Body), &cmd); err != nil {
		return resp(400, map[string]string{"error": "invalid json"})
	}

	cmd.DeviceID = strings.TrimSpace(cmd.DeviceID)
	if cmd.Token == "" || s.sharedSecret == "" || !timingSafeEq(cmd.Token, s.sharedSecret) {
		return resp(401, map[string]string{"error": "unauthorized"})
	}
	if cmd.DeviceID == "" {
		return resp(400, map[string]string{"error": "deviceId required"})
	}
	if cmd.Type != "wash" && cmd.Type != "dry" {
		return resp(400, map[string]string{"error": "type must be wash or dry"})
	}
	if cmd.DurationMinutes <= 0 {
		return resp(400, map[string]string{"error": "durationMinutes must be > 0"})
	}

	now := time.Now().UnixMilli()

	durationStr := strconv.Itoa(cmd.DurationMinutes)
	createdAtStr := strconv.FormatInt(now, 10)

	_, err := s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item: map[string]types.AttributeValue{
			"deviceId":        &types.AttributeValueMemberS{Value: cmd.DeviceID},
			"type":            &types.AttributeValueMemberS{Value: cmd.Type},
			"durationMinutes": &types.AttributeValueMemberN{Value: durationStr},
			"createdAt":       &types.AttributeValueMemberN{Value: createdAtStr},
			// servedAt intentionally NOT set (means "not served yet")
		},
	})
	if err != nil {
		return resp(500, map[string]string{
			"error": err.Error(),
			"table": s.table,
		})
	}

	return resp(200, map[string]any{"ok": true, "createdAt": now})
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
