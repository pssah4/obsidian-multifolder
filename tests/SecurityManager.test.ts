import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { SecurityManager } from '../src/SecurityManager';
import type { MountPoint } from '../src/types';

// Helper: temporarily override process.platform
function withPlatform(platform: NodeJS.Platform, fn: () => void): void {
	const orig = process.platform;
	Object.defineProperty(process, 'platform', { value: platform, configurable: true });
	try { fn(); } finally {
		Object.defineProperty(process, 'platform', { value: orig, configurable: true });
	}
}

function mkMount(virtualPath: string, realPath: string): Omit<MountPoint, 'id'> {
	return { virtualPath, realPath, enabled: true, readOnly: false };
}

describe('SecurityManager', () => {
	let sec: SecurityManager;

	beforeEach(() => {
		sec = new SecurityManager(['/allowed/path']);
	});

	describe('isAllowed', () => {
		it('allows an exact match to an allowlisted path', () => {
			expect(sec.isAllowed('/allowed/path')).toBe(true);
		});

		it('allows a subdirectory of an allowlisted path', () => {
			expect(sec.isAllowed('/allowed/path/subdir/file.md')).toBe(true);
		});

		it('rejects a path not in the allowlist', () => {
			expect(sec.isAllowed('/not/allowed')).toBe(false);
		});

		it('rejects a prefix-substring path that is not a subdirectory', () => {
			// /allowed/pathmore should NOT be allowed when /allowed/path is in list
			expect(sec.isAllowed('/allowed/pathmore')).toBe(false);
		});
	});

	describe('allow / revoke', () => {
		it('dynamically adds a path to the allowlist', () => {
			sec.allow('/new/path');
			expect(sec.isAllowed('/new/path/file.txt')).toBe(true);
		});

		it('revokes an allowlisted path', () => {
			sec.revoke('/allowed/path');
			expect(sec.isAllowed('/allowed/path')).toBe(false);
		});

		it('does not affect other entries when revoking', () => {
			sec.allow('/other');
			sec.revoke('/allowed/path');
			expect(sec.isAllowed('/other')).toBe(true);
		});
	});

	describe('validateMount', () => {
		it('returns null for a valid mount', () => {
			expect(sec.validateMount(mkMount('Work', '/home/user/Work'), [])).toBeNull();
		});

		it('rejects empty virtual path', () => {
			expect(sec.validateMount(mkMount('', '/home/user/Work'), [])).toMatch(/virtual path/i);
		});

		it('rejects empty real path', () => {
			expect(sec.validateMount(mkMount('Work', ''), [])).toMatch(/real path/i);
		});

		it('rejects a non-absolute real path', () => {
			expect(sec.validateMount(mkMount('Work', 'relative/path'), [])).toMatch(/absolute/i);
		});

		it('blocks the POSIX system root /', () => {
			expect(sec.validateMount(mkMount('Root', '/'), [])).toMatch(/protected/i);
		});

		it('blocks dangerous POSIX system paths like /etc', () => {
			expect(sec.validateMount(mkMount('Etc', '/etc'), [])).toMatch(/protected/i);
		});

		it('blocks /etc subdirectories', () => {
			expect(sec.validateMount(mkMount('Ssl', '/etc/ssl'), [])).toMatch(/protected/i);
		});

		it('rejects a duplicate virtual path', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'Work', realPath: '/real/Work', enabled: true, readOnly: false,
			}];
			const err = sec.validateMount(mkMount('Work', '/real/Other'), existing);
			expect(err).toMatch(/already in use/i);
		});

		it('rejects a virtual path that is a child of an existing mount', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'Projects', realPath: '/real/Projects', enabled: true, readOnly: false,
			}];
			const err = sec.validateMount(mkMount('Projects/Work', '/real/Work'), existing);
			expect(err).toMatch(/overlaps/i);
		});

		it('allows a real path that is a subdirectory of an existing mount real path (advisory warning only)', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'ParentMount', realPath: '/real/parent', enabled: true, readOnly: false,
			}];
			// No longer a blocking error — overlap is surfaced as an advisory warning instead
			const err = sec.validateMount(mkMount('ChildMount', '/real/parent/child'), existing);
			expect(err).toBeNull();
			expect(sec.getPathWarnings('/real/parent/child', existing).length).toBeGreaterThan(0);
		});

		it('allows Backup/Code-Scalpel and Backup to coexist as separate bridges', () => {
			// Scenario from issue: mount virtualPath "Code-Scalpel" → /Backup/Code-Scalpel first,
			// then mount virtualPath "Backup" → /Backup.  Real paths overlap; virtual paths do not.
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'Code-Scalpel', realPath: '/Backup/Code-Scalpel', enabled: true, readOnly: false,
			}];
			const err = sec.validateMount(mkMount('Backup', '/Backup'), existing);
			expect(err).toBeNull();
			// Overlap between /Backup and /Backup/Code-Scalpel should be surfaced as an advisory warning
			const warnings = sec.getPathWarnings('/Backup', existing);
			expect(warnings.length).toBeGreaterThan(0);
		});

	});

	describe('getPathWarnings', () => {
		it('returns a warning for UNC paths', () => {
			const warnings = sec.getPathWarnings('\\\\server\\share\\folder');
			expect(warnings.length).toBeGreaterThan(0);
			expect(warnings[0]).toMatch(/UNC|network/i);
		});

		it('returns no warnings for a normal local path with no existing mounts', () => {
			const warnings = sec.getPathWarnings('/home/user/docs');
			expect(warnings).toHaveLength(0);
		});

		it('returns an advisory warning when the candidate is a child of an existing mount real path', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'Backup', realPath: '/Backup', enabled: true, readOnly: false,
			}];
			const warnings = sec.getPathWarnings('/Backup/Code-Scalpel', existing);
			expect(warnings.length).toBeGreaterThan(0);
			expect(warnings[0]).toMatch(/overlaps/i);
		});

		it('returns an advisory warning when the candidate is a parent of an existing mount real path', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'CodeScalpel', realPath: '/Backup/Code-Scalpel', enabled: true, readOnly: false,
			}];
			const warnings = sec.getPathWarnings('/Backup', existing);
			expect(warnings.length).toBeGreaterThan(0);
			expect(warnings[0]).toMatch(/overlaps/i);
		});

		it('returns no overlap warning when the real paths are unrelated', () => {
			const existing: MountPoint[] = [{
				id: '1', virtualPath: 'Work', realPath: '/home/user/Work', enabled: true, readOnly: false,
			}];
			const warnings = sec.getPathWarnings('/home/user/Docs', existing);
			expect(warnings).toHaveLength(0);
		});
	});

	// Note: the Windows case-insensitive comparison (normalizeForComparison) is
	// tested in OSHelpers.test.ts. SecurityManager delegates to that function.
});

describe('SecurityManager symlink containment (H-2)', () => {
	const tmpRoot = path.join(os.tmpdir(), `fb-sec-${process.pid}`);
	const mountDir = path.join(tmpRoot, 'mount');
	const outsideDir = path.join(tmpRoot, 'outside');
	let sec: SecurityManager;

	beforeEach(() => {
		fs.rmSync(tmpRoot, { recursive: true, force: true });
		fs.mkdirSync(mountDir, { recursive: true });
		fs.mkdirSync(outsideDir, { recursive: true });
		fs.writeFileSync(path.join(outsideDir, 'secret.txt'), 'secret');
		fs.symlinkSync(outsideDir, path.join(mountDir, 'escape'));
		sec = new SecurityManager([mountDir]);
	});

	afterEach(() => {
		fs.rmSync(tmpRoot, { recursive: true, force: true });
	});

	it('rejects a path that leaves the allowlist through a symlinked directory', () => {
		expect(sec.isAllowed(path.join(mountDir, 'escape', 'secret.txt'))).toBe(false);
	});

	it('rejects the symlinked directory itself', () => {
		expect(sec.isAllowed(path.join(mountDir, 'escape'))).toBe(false);
	});

	it('still allows a real file inside the mount', () => {
		fs.writeFileSync(path.join(mountDir, 'real.md'), 'x');
		expect(sec.isAllowed(path.join(mountDir, 'real.md'))).toBe(true);
	});

	it('still allows a not-yet-existing path inside the mount (write targets)', () => {
		expect(sec.isAllowed(path.join(mountDir, 'new-note.md'))).toBe(true);
	});

	it('rejects a not-yet-existing path under a symlinked directory', () => {
		expect(sec.isAllowed(path.join(mountDir, 'escape', 'new-note.md'))).toBe(false);
	});
});

describe('SecurityManager input hardening (L-1)', () => {
	it('validates a virtual path with many trailing separators in linear time', () => {
		const sec = new SecurityManager(['/allowed/path']);
		// Trailing separators followed by a non-separator: the backtracking case.
		const mount = mkMount('Vault' + '/'.repeat(60000) + 'x', '/allowed/path');
		const started = Date.now();
		sec.validateMount(mount, []);
		expect(Date.now() - started).toBeLessThan(100);
	});
});
