import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Controls what getSafeStorage() finds inside CredentialStore.
let safeStorageAvailable = true;

vi.mock('../src/runtimeNode', () => ({
	getRuntimeRequire: () => (id: string) => {
		if (id !== 'electron') throw new Error(`unexpected module ${id}`);
		return {
			safeStorage: {
				isEncryptionAvailable: () => safeStorageAvailable,
				encryptString: (s: string) => Buffer.from(`enc(${s})`),
				decryptString: (b: Buffer) => b.toString().replace(/^enc\(|\)$/g, ''),
			},
		};
	},
	loadOptionalNodeModule: () => null,
}));

// Minimal sessionStorage spy: records every write.
const written = new Map<string, string>();
beforeEach(async () => {
	written.clear();
	safeStorageAvailable = true;
	vi.stubGlobal('sessionStorage', {
		setItem: (k: string, v: string) => { written.set(k, v); },
		getItem: (k: string) => written.get(k) ?? null,
		removeItem: (k: string) => { written.delete(k); },
	});
	const mod = await import('../src/CredentialStore');
	mod.clearSessionCredential('webdav', 'm1');
	mod.clearSessionCredential('s3', 'm1');
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('CredentialStore session credentials (M-1)', () => {
	it('round-trips a credential', async () => {
		const { saveSessionCredential, loadSessionCredential } = await import('../src/CredentialStore');
		saveSessionCredential('webdav', 'm1', 'hunter2');
		expect(loadSessionCredential('webdav', 'm1')).toBe('hunter2');
	});

	it('keeps the credential out of sessionStorage when OS encryption is available', async () => {
		const { saveSessionCredential } = await import('../src/CredentialStore');
		saveSessionCredential('webdav', 'm1', 'hunter2');
		expect([...written.values()]).not.toContain('hunter2');
		expect(written.size).toBe(0);
	});

	it('falls back to sessionStorage when OS encryption is unavailable (mobile)', async () => {
		safeStorageAvailable = false;
		const { saveSessionCredential, loadSessionCredential } = await import('../src/CredentialStore');
		saveSessionCredential('s3', 'm1', 'secretkey');
		expect([...written.values()]).toContain('secretkey');
		expect(loadSessionCredential('s3', 'm1')).toBe('secretkey');
	});

	it('clears a credential from both the memory store and sessionStorage', async () => {
		safeStorageAvailable = false;
		const { saveSessionCredential, clearSessionCredential, loadSessionCredential } =
			await import('../src/CredentialStore');
		saveSessionCredential('s3', 'm1', 'secretkey');
		clearSessionCredential('s3', 'm1');
		expect(loadSessionCredential('s3', 'm1')).toBeNull();
		expect(written.size).toBe(0);
	});

	it('keeps credentials of different mounts apart', async () => {
		const { saveSessionCredential, loadSessionCredential } = await import('../src/CredentialStore');
		saveSessionCredential('sftp-pw', 'mountA', 'aaa');
		saveSessionCredential('sftp-pw', 'mountB', 'bbb');
		expect(loadSessionCredential('sftp-pw', 'mountA')).toBe('aaa');
		expect(loadSessionCredential('sftp-pw', 'mountB')).toBe('bbb');
	});
});
