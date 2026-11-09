// Package store holds the interfaces of maap's tables (ADR 0009
// Consequences, group 4): maap-registry, maap-subscribers, maap-requests
// and maap-counters, which only maap's task role writes (§12). Each
// table's store and its memory backend come with the table (#708, #711,
// #713).
package store

import "context"

// ChatbotDeleter is implemented by the store of every table that keeps
// items of a chatbot. Deleting a chatbot calls it on each of them (#709),
// since that deletes the chatbot's aliases, conversations, blocks,
// idempotency records and statuses too (ADR 0009 §10).
type ChatbotDeleter interface {
	// DeleteChatbot deletes every item of the chatbot with the given ID.
	// It returns nil when there is none, so that a deletion that failed
	// part way can be called again to finish.
	DeleteChatbot(ctx context.Context, chatbotID string) error
}
