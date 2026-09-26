import { describe, expect, it } from 'vitest';
import { CLASSIFICATION_CONTENT_TYPE, bridgeOriginalIndex } from './bridgeAttest';

const att = (contentType: string, filename: string) => ({ contentType, filename });
const classification = att(CLASSIFICATION_CONTENT_TYPE, 'classification.bin');
const original = att('message/rfc822', 'original.eml');

describe('bridgeOriginalIndex', () => {
  it('finds the raw source the bridge seals right after its classification', () => {
    expect(bridgeOriginalIndex([classification, original, att('application/pdf', 'deck.pdf')])).toBe(1);
  });

  it('leaves a forwarded email alone: it is message/rfc822 but not in the bridge slot', () => {
    const forwarded = att('message/rfc822', 'Fwd intro.eml');
    expect(bridgeOriginalIndex([classification, original, forwarded])).toBe(1);
    expect(bridgeOriginalIndex([classification, forwarded])).toBe(-1);
  });

  it('finds nothing on mail the bridge did not relay', () => {
    expect(bridgeOriginalIndex([original])).toBe(-1);
    expect(bridgeOriginalIndex([att('application/pdf', 'x.pdf'), original])).toBe(-1);
    expect(bridgeOriginalIndex([])).toBe(-1);
  });
});
