import { MountPoint, MountType } from './types';
import { normalizeForComparison, isUNCPath, stripTrailingSeparators } from './OSHelpers';
import { loadOptionalNodeModule } from './runtimeNode';
// Node.js builtins are lazy-loaded so the plugin still loads on mobile
const path: typeof import('path') = loadOptionalNodeModule<typeof import('path')>('path') ?? null as never;
const fs: typeof import('fs') | null = loadOptionalNodeModule<typeof import('fs')>('fs');

/** Mount types whose realPath is a remote address, not a local filesystem path. */
const CLOUD_MOUNT_TYPES: Set<MountType> = new Set(['webdav', 's3', 'sftp']);

/** Upper bound on how far resolveSymlinks() walks up looking for an existing ancestor. */
const MAX_ANCESTOR_WALK = 64;
/** Upper bound on symlink hops, mirroring the kernel's ELOOP limit. */
const MAX_LINK_HOPS = 32;

/**
 * Resolve every symlink in `target` so containment can be checked against the
 * location the OS will actually open, not the textual path.
 *
 * A path that does not exist yet (a write target) has no realpath, so the
 * nearest existing ancestor is resolved and the remaining segments are
 * re-attached by reattachUnresolved(), which follows any symlink among them.
 *
 * Returns the input unchanged when `fs` is unavailable (mobile) or the walk
 * hits the filesystem root, which keeps the caller's textual check as the
 * fallback rather than failing open on an exception.
 */
function resolveSymlinks(target: string, hops = 0): string {
	if (!fs || hops > MAX_LINK_HOPS) return target;
	const pending: string[] = [];
	let current = target;
	for (let i = 0; i < MAX_ANCESTOR_WALK; i++) {
		try {
			const real = fs.realpathSync(current);
			if (!pending.length) return real;
			pending.reverse();
			return reattachUnresolved(real, pending, hops);
		} catch {
			const parent = path.dirname(current);
			if (!parent || parent === current) return target;
			pending.push(path.basename(current));
			current = parent;
		}
	}
	return target;
}

/**
 * Append segments that realpathSync() could not resolve, following any symlink
 * encountered on the way.
 *
 * A DANGLING symlink (one whose target does not exist yet) is the reason this
 * cannot simply path.join(): realpathSync() throws ENOENT on it exactly as it
 * does on a plain missing file, so it arrives here as an unresolved segment.
 * Joining it as text would report a contained path while the OS, opening with
 * O_CREAT, follows the link and creates the target outside the allowlist.
 */
function reattachUnresolved(base: string, segments: string[], hops: number): string {
	if (!fs) return path.join(base, ...segments);
	let resolved = base;
	for (let i = 0; i < segments.length; i++) {
		const candidate = path.join(resolved, segments[i]);
		let linkTarget: string | null = null;
		try {
			if (fs.lstatSync(candidate).isSymbolicLink()) {
				linkTarget = fs.readlinkSync(candidate);
			}
		} catch {
			// No lstat entry at all: a genuinely missing segment, and everything
			// below it is missing too. Nothing left that could be a link.
		}
		if (linkTarget !== null) {
			// A relative link resolves against the directory holding it.
			const absolute = path.resolve(path.dirname(candidate), linkTarget);
			const rest = segments.slice(i + 1);
			// Re-enter the full resolution so the target's own ancestors and any
			// further links in the chain are resolved as well.
			return resolveSymlinks(rest.length ? path.join(absolute, ...rest) : absolute, hops + 1);
		}
		resolved = candidate;
	}
	return resolved;
}

/**
 * SecurityManager enforces an explicit allowlist of real filesystem paths.
 * Every I/O operation on a mounted path is checked against this list before
 * proceeding.  On Windows, comparisons are case-insensitive to match NTFS
 * semantics (e.g. 'C:\Docs' and 'c:\docs' refer to the same location).
 */
export class SecurityManager {
	private allowlist: Set<string>;

	constructor(allowedPaths: string[]) {
		this.allowlist = new Set(allowedPaths.map(p => normalizeForComparison(resolveSymlinks(p))));
	}

	/** Replace the entire allowlist (call after settings change). */
	setAllowlist(paths: string[]): void {
		this.allowlist = new Set(paths.map(p => normalizeForComparison(resolveSymlinks(p))));
	}

	/**
	 * Returns true when realPath is equal to an allowlisted path, or is
	 * contained inside one.  The check is path-separator-aware to prevent
	 * prefix-substring false positives (e.g. "/foo" must not match "/foobar").
	 * On Windows the comparison is case-insensitive.
	 *
	 * Symlinks are resolved on both sides before comparing, so a link inside a
	 * mount that points outside it does not pass.  This is a check against the
	 * filesystem state at call time; a link swapped between this check and the
	 * subsequent I/O call is not covered (CWE-367) and would need an
	 * openat/O_NOFOLLOW-based API to close completely.
	 */
	isAllowed(realPath: string): boolean {
		const normalized = normalizeForComparison(resolveSymlinks(realPath));
		for (const allowed of this.allowlist) {
			if (
				normalized === allowed ||
				normalized.startsWith(allowed + path.sep) ||
				// Case-insensitive comparison may produce lowercased sep; check both
				normalized.startsWith(allowed + '/')
			) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Validates a candidate mount before it is added to settings.
	 * Returns an error string on failure, or null on success.
	 */
	validateMount(
		mount: Omit<MountPoint, 'id'>,
		existingMounts: MountPoint[]
	): string | null {
		if (!mount.virtualPath || !mount.virtualPath.trim()) {
			return 'Virtual path cannot be empty.';
		}

		// Cloud mounts (WebDAV, S3, SFTP) don't have local real paths — skip local-path checks.
		const isCloud = mount.mountType != null && CLOUD_MOUNT_TYPES.has(mount.mountType);

		if (!isCloud) {
			if (!mount.realPath || !mount.realPath.trim()) {
				return 'Real path cannot be empty.';
			}
			if (!path.isAbsolute(mount.realPath)) {
				return 'Real path must be an absolute filesystem path.';
			}

			// Block obviously dangerous root-level paths and their subdirectories
			const dangerous = [
				'/', '/etc', '/usr', '/bin', '/sbin', '/boot', '/dev', '/proc', '/sys', '/var',
				'C:\\', 'C:/',
				'C:\\Windows', 'C:/Windows',
				'C:\\Program Files', 'C:/Program Files',
				'C:\\Program Files (x86)', 'C:/Program Files (x86)'
			];
			const norm = normalizeForComparison(mount.realPath);
			for (const d of dangerous) {
				const dangerousNorm = normalizeForComparison(d);
				if (
					norm === dangerousNorm ||
					norm.startsWith(dangerousNorm + path.sep) ||
					// Case-insensitive comparison may produce lowercased or normalized separators; check both
					norm.startsWith(dangerousNorm + '/')
				) {
					return `"${mount.realPath}" is a protected system path and cannot be mounted.`;
				}
			}
		}

		// Normalize virtual path (trim and remove trailing slashes) for comparison
		const virtualNorm = stripTrailingSeparators(mount.virtualPath.trim());

		// Reject duplicate virtual paths
		if (
			existingMounts.some(
				m => stripTrailingSeparators((m.virtualPath || '').trim()) === virtualNorm
			)
		) {
			return `Virtual path "${virtualNorm}" is already in use.`;
		}

		// Reject mounts whose virtual paths are parents/children of existing ones
		for (const m of existingMounts) {
			const existingVirtual = (m.virtualPath || '').trim();
			if (!existingVirtual) {
				continue;
			}
			const existingVirtualNorm = stripTrailingSeparators(existingVirtual);
			if (!existingVirtualNorm || existingVirtualNorm === virtualNorm) {
				continue;
			}

			// Check for path-separator-aware parent/child relationships
			const isCandidateChildOfExisting =
				virtualNorm.startsWith(existingVirtualNorm + path.sep) ||
				virtualNorm.startsWith(existingVirtualNorm + '/');
			const isExistingChildOfCandidate =
				existingVirtualNorm.startsWith(virtualNorm + path.sep) ||
				existingVirtualNorm.startsWith(virtualNorm + '/');

			if (isCandidateChildOfExisting || isExistingChildOfCandidate) {
				return `Virtual path "${virtualNorm}" overlaps with existing mount "${existingVirtualNorm}".`;
			}
		}

		return null;
	}

	/**
	 * Returns non-blocking advisory warnings for a real path.
	 * Unlike validateMount(), these do not prevent the mount from being added —
	 * they are surfaced to the user as informational notices.
	 *
	 * Pass `existingMounts` to also receive overlap advisories when the
	 * candidate real path is a parent or child of an already-mounted path.
	 */
	getPathWarnings(realPath: string, existingMounts: MountPoint[] = [], mountType?: MountType): string[] {
		const warnings: string[] = [];

		// Cloud mounts use remote addresses, not local paths — skip all local-path warnings.
		if (mountType != null && CLOUD_MOUNT_TYPES.has(mountType)) return warnings;

		if (isUNCPath(realPath)) {
			warnings.push(
				`"${realPath}" is a UNC network path. Network mounts may be slow, ` +
				`unavailable offline, or behave differently from local folders ` +
				`(e.g. file watching may not work on some servers).`
			);
		}

		const norm = normalizeForComparison(realPath);
		for (const m of existingMounts) {
			const existingReal = m.realPath;
			if (!existingReal) continue;
			const existingRealNorm = normalizeForComparison(existingReal);
			if (existingRealNorm === norm) continue;

			const isCandidateChildOfExisting =
				norm.startsWith(existingRealNorm + path.sep) ||
				norm.startsWith(existingRealNorm + '/');
			const isExistingChildOfCandidate =
				existingRealNorm.startsWith(norm + path.sep) ||
				existingRealNorm.startsWith(norm + '/');

			if (isCandidateChildOfExisting || isExistingChildOfCandidate) {
				warnings.push(
					`Real path "${realPath}" overlaps with existing mount "${existingReal}". ` +
					`The same files on disk will be reachable via two different vault paths.`
				);
			}
		}

		return warnings;
	}

	/** Add a path to the allowlist. */
	allow(realPath: string): void {
		this.allowlist.add(normalizeForComparison(realPath));
	}

	/** Remove a path from the allowlist. */
	revoke(realPath: string): void {
		this.allowlist.delete(normalizeForComparison(realPath));
	}

	getAllowedPaths(): string[] {
		return Array.from(this.allowlist);
	}
}
