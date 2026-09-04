import { describe, it, expect } from 'vitest';
import { classifyRemoteUrl } from '../src/OSHelpers';

describe('classifyRemoteUrl (M-3)', () => {
	it('accepts an https URL', () => {
		expect(classifyRemoteUrl('https://cloud.example.com/dav')).toEqual({ ok: true });
	});

	it('rejects a plain http URL to a remote host', () => {
		const r = classifyRemoteUrl('http://cloud.example.com/dav');
		expect(r.ok).toBe(false);
		expect(r.reason).toMatch(/https/i);
	});

	it('allows http to localhost for local test servers', () => {
		expect(classifyRemoteUrl('http://localhost:8080/dav').ok).toBe(true);
		expect(classifyRemoteUrl('http://127.0.0.1:8080/dav').ok).toBe(true);
		expect(classifyRemoteUrl('http://[::1]:8080/dav').ok).toBe(true);
	});

	it('rejects an unparseable URL', () => {
		expect(classifyRemoteUrl('not a url').ok).toBe(false);
	});

	it('rejects an empty URL', () => {
		expect(classifyRemoteUrl('   ').ok).toBe(false);
	});

	it('rejects a non-http scheme', () => {
		expect(classifyRemoteUrl('file:///etc/passwd').ok).toBe(false);
		expect(classifyRemoteUrl('javascript:alert(1)').ok).toBe(false);
	});

	it('does not treat a host merely containing localhost as local', () => {
		expect(classifyRemoteUrl('http://localhost.evil.com/dav').ok).toBe(false);
	});
});
