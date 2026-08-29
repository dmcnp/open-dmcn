package message

import "testing"

// A signer can seal a header whose snippet disagrees with its own body: both halves are
// signed, only the body is bound. VerifySnippet is what makes that visible.
func TestVerifySnippet(t *testing.T) {
	body := MessageBody{ContentType: "text/plain", Content: []byte("The actual message body.")}
	content := &MessageContent{Body: body}

	honest := &MessageHeader{Snippet: snippetOf(body)}
	if !VerifySnippet(honest, content) {
		t.Error("a snippet derived from the body did not verify")
	}

	lying := &MessageHeader{Snippet: "Your invoice is ready — click to view"}
	if VerifySnippet(lying, content) {
		t.Error("a snippet that disagrees with the body verified")
	}

	// An empty snippet on a non-text body is correct, not a mismatch.
	binary := &MessageContent{Body: MessageBody{ContentType: "application/octet-stream", Content: []byte{1, 2, 3}}}
	if !VerifySnippet(&MessageHeader{Snippet: ""}, binary) {
		t.Error("an empty snippet for a non-text body should verify")
	}

	// A truncated body still verifies: the snippet is a prefix by construction.
	long := MessageBody{ContentType: "text/plain", Content: make([]byte, 500)}
	for i := range long.Content {
		long.Content[i] = 'a'
	}
	if !VerifySnippet(&MessageHeader{Snippet: snippetOf(long)}, &MessageContent{Body: long}) {
		t.Error("a truncated snippet did not verify against its own body")
	}

	if VerifySnippet(nil, content) || VerifySnippet(honest, nil) {
		t.Error("nil inputs should not verify")
	}
}
