package bridge

import (
	"context"
	"sync"

	"dmcn.dev/open-dmcn/internal/core/message"
)

// DeliveredMessage records a message captured by StubSMTPDeliverer.
type DeliveredMessage struct {
	From        string
	To          string
	Subject     string
	Body        string // string(msg.Body.Content), for convenient test assertions
	ContentType string
	Attachments []message.AttachmentRecord
	Msg         *message.PlaintextMessage // the full message, for fidelity assertions
	// Audience is the shared To/Cc the message was addressed to — what Reply All depends on.
	Audience Audience
}

// StubSMTPDeliverer is an SMTPDeliverer that captures messages in memory
// for test assertions instead of delivering via SMTP.
type StubSMTPDeliverer struct {
	mu       sync.Mutex
	Messages []DeliveredMessage
}

// Deliver records the message for later inspection.
func (s *StubSMTPDeliverer) Deliver(_ context.Context, from, to string, msg *message.PlaintextMessage, audience Audience) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Messages = append(s.Messages, DeliveredMessage{
		From:        from,
		To:          to,
		Subject:     msg.Subject,
		Body:        string(msg.Body.Content),
		ContentType: msg.Body.ContentType,
		Attachments: msg.Attachments,
		Msg:         msg,
		Audience:    audience,
	})
	return nil
}
