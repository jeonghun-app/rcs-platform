package awsstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// A chatbot's deletion is bounded and paced (lead decision on #713, after
// the operations review of #751): a chatbot at its send limits holds
// about 180,000 items, more than one call under the API's 30 s write
// timeout can delete at a pace that leaves the partitions it shares with
// other chatbots their capacity. So each batch of batchSize items, the
// most a BatchWriteItem takes, waits for batchPace after the one before
// (250 items a second), and a deletion stops deadlineMargin before its
// context's deadline with store.ErrUnfinished; a call again goes on from
// what is left.
const (
	batchSize      = 25
	deadlineMargin = 2 * time.Second
	// batchAttempts bounds the sends of a batch whose items DynamoDB
	// keeps leaving unprocessed (throttling): a deletion that gives up is
	// a store failure, and a repeat goes on where it stopped.
	batchAttempts = 8
)

// batchPace and batchWait, the first pause before a batch is sent again
// (doubling after), are variables for tests.
var (
	batchPace = 100 * time.Millisecond
	batchWait = 50 * time.Millisecond
)

// deletePartition deletes every item of partition pk, the chatbot's in
// table, and logs one line of progress: counts only, and the chatbot's
// ID, which is no subscriber's.
func deletePartition(ctx context.Context, api TableAPI, table, pk, chatbotID string, pageSize int32) (err error) {
	deleted := 0
	defer func() { logProgress(table, chatbotID, deleted, err) }()
	in := &dynamodb.QueryInput{
		TableName: aws.String(table), ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ProjectionExpression:      aws.String("#pk, #sk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": str(pk)},
	}
	if pageSize > 0 {
		in.Limit = aws.Int32(pageSize)
	}
	var last time.Time
	for {
		out, err := api.Query(ctx, in)
		if err != nil {
			return unfinished(ctx, sanitize("query chatbot", err))
		}
		for items := out.Items; len(items) > 0; {
			if err := pace(ctx, last); err != nil {
				return err
			}
			last = time.Now()
			n := min(len(items), batchSize)
			if err := deleteBatch(ctx, api, table, items[:n]); err != nil {
				return unfinished(ctx, err)
			}
			deleted += n
			items = items[n:]
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// logProgress logs a chatbot deletion's progress in one table: counts
// only, and the chatbot's ID, which is no subscriber's.
func logProgress(table, chatbotID string, deleted int, err error) {
	if deleted > 0 || err != nil {
		slog.Info("awsstore: chatbot deletion progress", slog.String("table", table), slog.String("chatbot", chatbotID),
			slog.Int("deleted", deleted), slog.Bool("finished", err == nil))
	}
}

// pace waits until batchPace after last, or returns store.ErrUnfinished
// when the context's deadline would come within deadlineMargin of it.
func pace(ctx context.Context, last time.Time) error { return paceEvery(ctx, last, batchPace) }

// paceEvery is pace for writes every interval apart: the alias deletions
// of maap-subscribers, one transaction of two items each, go by their own.
func paceEvery(ctx context.Context, last time.Time, interval time.Duration) error {
	start := last.Add(interval)
	if dl, ok := ctx.Deadline(); ok && dl.Sub(start) < deadlineMargin {
		return store.ErrUnfinished
	}
	if wait := time.Until(start); wait > 0 {
		select {
		case <-ctx.Done():
			return unfinished(ctx, fmt.Errorf("awsstore: delete chatbot: %w", ctx.Err()))
		case <-time.After(wait):
		}
	}
	return nil
}

// unfinished turns err, when it came from the context's deadline, into
// store.ErrUnfinished: a call again goes on.
func unfinished(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w (%w)", store.ErrUnfinished, err)
	}
	return err
}

func deleteBatch(ctx context.Context, api TableAPI, table string, keys []map[string]types.AttributeValue) error {
	reqs := make([]types.WriteRequest, len(keys))
	for i, k := range keys {
		reqs[i] = types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(sv(k[attrPK]), sv(k[attrSK]))}}
	}
	for attempt, wait := 0, batchWait; ; attempt, wait = attempt+1, 2*wait {
		out, err := api.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{table: reqs}})
		if err != nil {
			return sanitize("delete chatbot", err)
		}
		if reqs = out.UnprocessedItems[table]; len(reqs) == 0 {
			return nil
		}
		if attempt == batchAttempts-1 {
			return errors.New("awsstore: delete chatbot: items left unprocessed")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("awsstore: delete chatbot: %w", ctx.Err())
		case <-time.After(wait):
		}
	}
}
