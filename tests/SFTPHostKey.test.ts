import { describe, it, expect, vi } from 'vitest';
import * as crypto from 'crypto';
import { createHostVerifier, fingerprintHostKey } from '../src/SFTPAdapter';

const KEY_A = Buffer.from('ssh-ed25519 AAAA-host-key-of-the-real-server');
const KEY_B = Buffer.from('ssh-ed25519 AAAA-host-key-of-an-impostor');

function sha256Base64(buf: Buffer): string {
	return crypto.createHash('sha256').update(buf).digest('base64').replace(/=+$/, '');
}

describe('fingerprintHostKey', () => {
	it('produces the OpenSSH-style SHA256 fingerprint', () => {
		expect(fingerprintHostKey(KEY_A)).toBe(`SHA256:${sha256Base64(KEY_A)}`);
	});

	it('produces different fingerprints for different keys', () => {
		expect(fingerprintHostKey(KEY_A)).not.toBe(fingerprintHostKey(KEY_B));
	});
});

describe('createHostVerifier (H-1)', () => {
	it('accepts the key that matches the pinned fingerprint', () => {
		const verify = createHostVerifier({ knownFingerprint: fingerprintHostKey(KEY_A) });
		expect(verify(KEY_A)).toBe(true);
	});

	it('rejects a key that does not match the pinned fingerprint', () => {
		const verify = createHostVerifier({ knownFingerprint: fingerprintHostKey(KEY_A) });
		expect(verify(KEY_B)).toBe(false);
	});

	it('does not re-learn a fingerprint once one is pinned', () => {
		const onLearn = vi.fn();
		const verify = createHostVerifier({ knownFingerprint: fingerprintHostKey(KEY_A), onLearn });
		verify(KEY_B);
		expect(onLearn).not.toHaveBeenCalled();
	});

	it('accepts and reports the first key when nothing is pinned yet (trust on first use)', () => {
		const onLearn = vi.fn();
		const verify = createHostVerifier({ onLearn });
		expect(verify(KEY_A)).toBe(true);
		expect(onLearn).toHaveBeenCalledWith(fingerprintHostKey(KEY_A));
	});

	it('pins the learned key for the rest of the session', () => {
		const verify = createHostVerifier({ onLearn: () => undefined });
		expect(verify(KEY_A)).toBe(true);
		expect(verify(KEY_B)).toBe(false);
	});

	it('rejects an empty key rather than treating it as unknown', () => {
		const verify = createHostVerifier({ knownFingerprint: fingerprintHostKey(KEY_A) });
		expect(verify(Buffer.alloc(0))).toBe(false);
	});
});
