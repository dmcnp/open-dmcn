package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	_ "github.com/emersion/go-message/charset" // register common charsets for inbound decoding
	"github.com/emersion/go-message/mail"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// This file maps between DMCN's PlaintextMessage model and RFC 5322 MIME so the bridge preserves
// fidelity in both directions: outbound (DMCN → legacy) renders the body's content type, every
// attachment, and threading headers; inbound (legacy → DMCN) parses the real subject, the body,
// each attachment, and the threading chain rather than dumping the raw source into a text/plain
// body. Threading is bridged by deriving DMCN's 16-byte IDs from RFC 5322 Message-IDs (and vice
// versa) so a conversation stays linked on either side.

// buildMIME renders a DMCN message as an RFC 5322 MIME message for SMTP delivery. from/to are the
// SMTP envelope-aligned addresses (already rewritten + injection-checked by the caller). The body
// keeps its content type; attachments become MIME attachment parts; the Message-ID and any
// In-Reply-To/References are derived deterministically from the DMCN message IDs so replies thread
// in the recipient's mail client.
func buildMIME(from, to string, msg *message.PlaintextMessage, now time.Time) ([]byte, error) {
	// Defence in depth: the OutboundHandler already rejects CR/LF in these and the library encodes
	// header values, but never build a message from a header field carrying a newline.
	if strings.ContainsAny(from, "\r\n") || strings.ContainsAny(to, "\r\n") || strings.ContainsAny(msg.Subject, "\r\n") {
		return nil, fmt.Errorf("smtp: header contains a newline (injection attempt)")
	}
	domain := domainOf(from)

	var h mail.Header
	h.SetAddressList("From", []*mail.Address{{Address: from}})
	h.SetAddressList("To", []*mail.Address{{Address: to}})
	h.SetSubject(msg.Subject)
	h.SetDate(now)
	h.Set("Message-ID", mailMsgID(msg.MessageID, domain))
	if msg.ReplyToID != ([16]byte{}) {
		ref := mailMsgID(msg.ReplyToID, domain)
		h.Set("In-Reply-To", ref)
		h.Set("References", ref)
	}

	bodyCT := msg.Body.ContentType
	if bodyCT == "" {
		bodyCT = "text/plain"
	}

	// No attachments → a simple single-part message (no multipart/mixed wrapper) — what MUAs emit
	// for plain mail and what receivers expect.
	if len(msg.Attachments) == 0 {
		h.SetContentType(bodyCT, map[string]string{"charset": "utf-8"})
		var buf bytes.Buffer
		w, err := mail.CreateSingleInlineWriter(&buf, h)
		if err != nil {
			return nil, fmt.Errorf("smtp: create writer: %w", err)
		}
		if _, err := w.Write(msg.Body.Content); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	// With attachments → multipart/mixed: the body as an inline part, then each attachment.
	var buf bytes.Buffer
	mw, err := mail.CreateWriter(&buf, h)
	if err != nil {
		return nil, fmt.Errorf("smtp: create writer: %w", err)
	}
	var ih mail.InlineHeader
	ih.SetContentType(bodyCT, map[string]string{"charset": "utf-8"})
	iw, err := mw.CreateSingleInline(ih)
	if err != nil {
		return nil, fmt.Errorf("smtp: create inline body: %w", err)
	}
	if _, err := iw.Write(msg.Body.Content); err != nil {
		return nil, err
	}
	if err := iw.Close(); err != nil {
		return nil, err
	}

	// Attachments (the bridge classification record + any user attachments).
	for _, a := range msg.Attachments {
		var ah mail.AttachmentHeader
		actype := a.ContentType
		if actype == "" {
			actype = "application/octet-stream"
		}
		ah.SetContentType(actype, nil)
		if a.Filename != "" {
			ah.SetFilename(a.Filename)
		}
		aw, err := mw.CreateAttachment(ah)
		if err != nil {
			return nil, fmt.Errorf("smtp: create attachment: %w", err)
		}
		if _, err := aw.Write(a.Content); err != nil {
			return nil, err
		}
		if err := aw.Close(); err != nil {
			return nil, err
		}
	}

	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("smtp: close writer: %w", err)
	}
	return buf.Bytes(), nil
}

// parsedMail is the fidelity-preserving result of parsing an inbound RFC 5322 message.
type parsedMail struct {
	Subject     string
	Body        message.MessageBody
	Attachments []message.AttachmentRecord
	MessageID   [16]byte // derived from the email Message-ID
	ThreadID    [16]byte // derived from References root / In-Reply-To / Message-ID
	ReplyToID   [16]byte // derived from In-Reply-To (zero ⇒ not a reply)
	HasIDs      bool     // the email carried a Message-ID we mapped onto the DMCN IDs
}

// parseInboundMIME parses a raw inbound email into a fidelity-preserving form: the decoded subject,
// the body (preferring text/plain, falling back to text/html), every attachment, and the threading
// chain mapped onto DMCN's 16-byte IDs. The caller still preserves the raw original as a separate
// attachment, so the unparsed source — and any alternative body part — is never lost.
func parseInboundMIME(raw []byte) (*parsedMail, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("bridge: parse mail: %w", err)
	}
	out := &parsedMail{}
	if subject, serr := mr.Header.Subject(); serr == nil {
		out.Subject = subject
	}

	// Threading: map the RFC 5322 Message-ID / In-Reply-To / References onto DMCN's 16-byte IDs so
	// a legacy conversation stays threaded on the DMCN side.
	if mid, merr := mr.Header.MessageID(); merr == nil && mid != "" {
		out.MessageID = deriveID(mid)
		out.HasIDs = true
	}
	if irt, ierr := mr.Header.MsgIDList("In-Reply-To"); ierr == nil && len(irt) > 0 {
		out.ReplyToID = deriveID(irt[0])
	}
	switch refs, rerr := mr.Header.MsgIDList("References"); {
	case rerr == nil && len(refs) > 0:
		out.ThreadID = deriveID(refs[0]) // conversation root
	case out.ReplyToID != ([16]byte{}):
		out.ThreadID = out.ReplyToID
	case out.HasIDs:
		out.ThreadID = out.MessageID
	}

	var plain, html []byte
	for {
		p, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			return nil, fmt.Errorf("bridge: read part: %w", perr)
		}
		data, derr := io.ReadAll(p.Body)
		if derr != nil {
			return nil, fmt.Errorf("bridge: read part body: %w", derr)
		}
		switch hdr := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := hdr.ContentType()
			switch {
			case strings.HasPrefix(ct, "text/plain"):
				if plain == nil {
					plain = data
				}
			case strings.HasPrefix(ct, "text/html"):
				if html == nil {
					html = data
				}
			default:
				out.Attachments = append(out.Attachments, mkAttachment("", ct, data))
			}
		case *mail.AttachmentHeader:
			filename, _ := hdr.Filename()
			ct, _, _ := hdr.ContentType()
			out.Attachments = append(out.Attachments, mkAttachment(filename, ct, data))
		}
	}

	// Prefer text/plain for the body (most compatible for DMCN clients); fall back to HTML. The
	// raw original is preserved as an attachment by the caller, so the alternative isn't lost.
	switch {
	case plain != nil:
		out.Body = message.MessageBody{ContentType: "text/plain", Content: plain}
	case html != nil:
		out.Body = message.MessageBody{ContentType: "text/html", Content: html}
	default:
		out.Body = message.MessageBody{ContentType: "text/plain"}
	}
	return out, nil
}

// mailMsgID renders a DMCN 16-byte ID as an RFC 5322 Message-ID scoped to the bridge domain.
func mailMsgID(id [16]byte, domain string) string {
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(id[:]), domain)
}

// deriveID maps an RFC 5322 Message-ID string onto a DMCN 16-byte ID — deterministic, so the same
// Message-ID always yields the same DMCN ID and threading relationships are preserved.
func deriveID(s string) [16]byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	var id [16]byte
	copy(id[:], sum[:16])
	return id
}

// mkAttachment builds a DMCN AttachmentRecord from a parsed MIME part.
func mkAttachment(filename, contentType string, content []byte) message.AttachmentRecord {
	id, _ := crypto.RandomUUID() // a zero ID is acceptable if entropy is briefly unavailable
	if filename == "" {
		filename = "attachment"
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return message.AttachmentRecord{
		AttachmentID: id,
		Filename:     filename,
		ContentType:  contentType,
		SizeBytes:    uint64(len(content)),
		ContentHash:  crypto.SHA256Hash(content),
		Content:      content,
	}
}
