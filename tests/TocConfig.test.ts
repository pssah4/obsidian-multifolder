import { describe, expect, it } from 'vitest';
import { parseTocConfig, serializeTocConfig } from '../src/TocConfig';
import type { MountPoint } from '../src/types';

describe('parseTocConfig', () => {
    it('parses local and vault mounts with ignore aliases', () => {
        const parsed = parseTocConfig(JSON.stringify({
            version: 1,
            mounts: [
                {
                    virtualPath: 'Projects',
                    realPath: '/data/projects',
                    ignore: ['node_modules', '.git'],
                },
                {
                    virtualPath: 'Shared',
                    realPath: '/data/shared-vault',
                    mountType: 'vault',
                    readOnly: true,
                },
            ],
        }), '/configs/multifolder.mounts.json', 'device-123');

        expect(parsed.warnings).toEqual([]);
        expect(parsed.mounts).toHaveLength(2);
        expect(parsed.mounts[0].ignoreList).toEqual(['node_modules', '.git']);
        expect(parsed.mounts[0].tocSourcePath).toBe('/configs/multifolder.mounts.json');
        expect(parsed.mounts[1].mountType).toBe('vault');
        expect(parsed.mounts[1].readOnly).toBe(true);
    });

    it('returns warnings for invalid entries and unsupported mount types', () => {
        const parsed = parseTocConfig(JSON.stringify({
            mounts: [
                { virtualPath: 'Bad', realPath: '' },
                { virtualPath: 'Cloud', realPath: '/tmp/cloud', mountType: 'webdav' },
            ],
        }), '/configs/bad.json', 'device-123');

        expect(parsed.mounts).toHaveLength(0);
        expect(parsed.warnings).toHaveLength(2);
    });

    it('preserves advanced watcher and device override settings for complex mount layouts', () => {
        const parsed = parseTocConfig(JSON.stringify({
            version: 1,
            mounts: [
                {
                    virtualPath: 'Projects/Client A/Active',
                    realPath: '/srv/client-a',
                    label: 'Client A active',
                    ignoreList: ['node_modules', 'dist', 'tmp/cache'],
                    visibleFileFilter: 'markdown-only',
                    watcherDebounceMs: 750,
                    watcherUsePolling: true,
                    watcherPollingIntervalMs: 5000,
                    watcherCreateFilter: 'markdown-only',
                    watcherSuppressAllEvents: true,
                    maxFiles: 25000,
                    deviceOverrides: {
                        'laptop-1': '/Users/me/ClientA',
                        'linux-box': '/mnt/data/client-a',
                    },
                },
            ],
        }), '/configs/complex.json', 'device-123');

        expect(parsed.warnings).toEqual([]);
        expect(parsed.mounts).toHaveLength(1);
        expect(parsed.mounts[0]).toMatchObject({
            virtualPath: 'Projects/Client A/Active',
            realPath: '/srv/client-a',
            label: 'Client A active',
            ignoreList: ['node_modules', 'dist', 'tmp/cache'],
            visibleFileFilter: 'markdown-only',
            watcherDebounceMs: 750,
            watcherUsePolling: true,
            watcherPollingIntervalMs: 5000,
            watcherCreateFilter: 'markdown-only',
            watcherSuppressAllEvents: true,
            maxFiles: 25000,
            deviceOverrides: {
                'laptop-1': '/Users/me/ClientA',
                'linux-box': '/mnt/data/client-a',
            },
        });
    });

    it('normalizes whitespace and ignores empty ignore entries', () => {
        const parsed = parseTocConfig(JSON.stringify({
            mounts: [
                {
                    virtualPath: '  Reference//Papers/  ',
                    realPath: '  /data/papers  ',
                    ignore: ['  .git  ', '', '   ', 'drafts/tmp  '],
                },
            ],
        }), '/configs/trim.json', 'device-123');

        expect(parsed.warnings).toEqual([]);
        expect(parsed.mounts[0].virtualPath).toBe('Reference/Papers');
        expect(parsed.mounts[0].realPath).toBe('/data/papers');
        expect(parsed.mounts[0].ignoreList).toEqual(['.git', 'drafts/tmp']);
    });

    it('preserves explicit ids and device ids from managed TOC files', () => {
        const parsed = parseTocConfig(JSON.stringify({
            mounts: [
                {
                    id: 'managed-alpha',
                    deviceId: 'desktop-42',
                    virtualPath: 'Projects/Alpha',
                    realPath: '/srv/alpha',
                },
            ],
        }), '/configs/managed.json', 'fallback-device');

        expect(parsed.warnings).toEqual([]);
        expect(parsed.mounts[0].id).toBe('managed-alpha');
        expect(parsed.mounts[0].deviceId).toBe('desktop-42');
    });

    it('serializes editable mounts without runtime-only TOC fields', () => {
        const text = serializeTocConfig([
            {
                id: 'managed-alpha',
                deviceId: 'desktop-42',
                virtualPath: 'Projects/Alpha',
                realPath: '/srv/alpha',
                enabled: true,
                readOnly: false,
                ignoreList: ['node_modules'],
                mountType: 'local',
                tocSourcePath: '/configs/managed.json',
            } satisfies MountPoint,
        ]);

        expect(text).toContain('"managed-alpha"');
        expect(text).toContain('"deviceId"');
        expect(text).not.toContain('tocSourcePath');

        const reparsed = parseTocConfig(text, '/configs/managed.json', 'fallback-device');
        expect(reparsed.warnings).toEqual([]);
        expect(reparsed.mounts[0].id).toBe('managed-alpha');
        expect(reparsed.mounts[0].deviceId).toBe('desktop-42');
        expect(reparsed.mounts[0].tocSourcePath).toBe('/configs/managed.json');
    });
});
