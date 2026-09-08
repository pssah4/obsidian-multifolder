import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { isPathWithinRoots, normalizeRootForServing } from '../src/FileServer';

const ROOT = path.resolve('/srv/vault/external');
const roots = new Set([normalizeRootForServing(ROOT)]);

describe('isPathWithinRoots (M-2)', () => {
	it('serves a file directly inside a root', () => {
		expect(isPathWithinRoots(`${ROOT}/clip.mp4`, roots)).toBe(true);
	});

	it('serves the root itself', () => {
		expect(isPathWithinRoots(ROOT, roots)).toBe(true);
	});

	it('serves a file in a nested directory', () => {
		expect(isPathWithinRoots(`${ROOT}/media/sub/clip.mp4`, roots)).toBe(true);
	});

	it('rejects a traversal that climbs out of the root', () => {
		expect(isPathWithinRoots(`${ROOT}/../../../../etc/passwd`, roots)).toBe(false);
	});

	it('rejects a traversal into a sibling directory', () => {
		expect(isPathWithinRoots(`${ROOT}/../secrets/id_rsa`, roots)).toBe(false);
	});

	it('rejects a traversal that ends back inside a differently-named sibling', () => {
		expect(isPathWithinRoots(`${ROOT}/../externalOther/file.txt`, roots)).toBe(false);
	});

	it('rejects a prefix-substring sibling of the root', () => {
		expect(isPathWithinRoots(`${ROOT}-backup/file.txt`, roots)).toBe(false);
	});

	it('rejects a path outside every root', () => {
		expect(isPathWithinRoots('/etc/passwd', roots)).toBe(false);
	});

	it('rejects an empty path', () => {
		expect(isPathWithinRoots('', roots)).toBe(false);
	});

	it('rejects everything when no root is registered', () => {
		expect(isPathWithinRoots(`${ROOT}/clip.mp4`, new Set())).toBe(false);
	});
});

describe('normalizeRootForServing input hardening', () => {
	it('normalizes a root with many trailing separators in linear time', () => {
		const started = Date.now();
		normalizeRootForServing('/srv/vault/' + '/'.repeat(60000) + 'x');
		expect(Date.now() - started).toBeLessThan(100);
	});

	it('still strips a single trailing separator', () => {
		expect(normalizeRootForServing('/srv/vault/external/')).toBe(path.resolve('/srv/vault/external'));
	});
});
