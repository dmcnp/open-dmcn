// fromPlainText lifts plain text into the HTML the rich composer edits. Used to seed the
// editor from the (plain-text) account signature, to quote a plain-text original in an
// HTML reply, and when the user switches a message from plain to rich mode.
//
// Escaping here is the point: the input is user/sender text that must never be parsed as
// markup. Everything downstream still runs through sanitizeOutgoing, but this is the
// boundary where "text" stops and "HTML" begins, so it escapes rather than trusting it.

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, c => ESCAPES[c]);
}

// fromPlainText escapes the text and preserves its line structure: blank-line-separated
// paragraphs become <div>s and single newlines become <br>, which is the shape
// contentEditable itself produces (so switching modes round-trips cleanly).
export function fromPlainText(text: string): string {
  if (!text) return '';
  return text
    .split(/\n{2,}/)
    .map(block => `<div>${escapeHtml(block).replace(/\n/g, '<br>')}</div>`)
    .join('<div><br></div>');
}
