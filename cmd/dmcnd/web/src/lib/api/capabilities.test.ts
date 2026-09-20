import { describe, it, expect } from 'vitest';
import { NO_CAPABILITIES } from './client';

// The default a caller gets when the answer cannot be established. It is asserted rather than
// assumed because the whole mechanism turns on it: a deployment whose backend predates the
// endpoint answers 404, and anything other than a flat "no" there would let a client proceed
// with an operation it cannot take back.
describe('NO_CAPABILITIES', () => {
  it('denies every capability', () => {
    expect(NO_CAPABILITIES.rotation.fleet_ready).toBe(false);
    expect(NO_CAPABILITIES.rotation.domain_allows).toBe(false);
  });

  it('carries no device-age allowance to fall back on', () => {
    // A non-zero default here would read as permission on a deployment that never answered.
    expect(NO_CAPABILITIES.rotation.min_device_age_days).toBe(0);
  });
});
