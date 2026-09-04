import { describe, it, expect } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { PathMapper } from '../src/PathMapper';
import { SecurityManager } from '../src/SecurityManager';
import { VirtualAdapter } from '../src/VirtualAdapter';

describe('E2E: the reported attack chain', () => {
    it('a planted dangling symlink cannot be written through', async () => {
        const root = await fs.mkdtemp(path.join(os.tmpdir(), 'fb-e2e-'));
        const mountDir = path.join(root, 'mount');
        const autostart = path.join(root, 'LaunchAgents');
        await fs.mkdir(mountDir);
        await fs.mkdir(autostart);

        // Attacker plants a link named after a file the victim will create.
        const payloadTarget = path.join(autostart, 'com.evil.plist');
        await fs.symlink(payloadTarget, path.join(mountDir, 'Report 1.md'));

        const mount = { id: 'm', virtualPath: 'Mounted', realPath: mountDir, enabled: true, readOnly: false };
        const mapper = new PathMapper();
        mapper.update([mount], 'dev');
        const adapter = new VirtualAdapter(
            {}, mapper, new SecurityManager([mountDir]), false, 10 * 1024 * 1024,
            async () => 'delete', async () => { }, () => false,
        );

        await expect(adapter.write('Mounted/Report 1.md', '<plist>payload</plist>')).rejects.toThrow(/allowlist/i);
        await expect(fs.stat(payloadTarget)).rejects.toMatchObject({ code: 'ENOENT' });

        await fs.rm(root, { recursive: true, force: true });
    });
});
