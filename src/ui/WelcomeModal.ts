import { App, Modal, Setting } from 'obsidian';

/**
 * First-run welcome modal shown once when Multifolder is loaded with no
 * mounts configured.  Gives new users a quick orientation and a direct path
 * to adding their first mount without having to hunt through Settings.
 */
export class WelcomeModal extends Modal {
	private onAddMount: () => void;
	private onDismiss: () => void;

	constructor(app: App, onAddMount: () => void, onDismiss: () => void) {
		super(app);
		this.onAddMount = onAddMount;
		this.onDismiss = onDismiss;
	}

	onOpen(): void {
		const { contentEl } = this;
		contentEl.empty();
		const pluginName = 'Multifolder';
		const quickSwitcher = 'Quick Switcher';

		contentEl.createEl('h2', { text: `Welcome to ${pluginName}` });

		const descEl = contentEl.createDiv({ cls: 'multifolder-welcome-desc' });

		descEl.createEl('p', {
			text: `${pluginName} lets you mount external folders into your vault as seamless, native-feeling directories, with no copying, duplication, or symlinks required.`,
		}).addClass('multifolder-welcome-intro');

		descEl.createEl('p', { text: 'What you can mount' }).addClass('multifolder-welcome-intro');

		const list = descEl.createEl('ul', { cls: 'multifolder-feature-list' });
		for (const item of [
			'Local folders on this device (or a connected drive)',
			'WebDAV servers — Nextcloud, ownCloud, NAS, Synology',
			'Folders from another Obsidian vault on this device',
		]) {
			list.createEl('li', { text: item, cls: 'multifolder-feature-item' });
		}

		descEl.createEl('p', {
			text: `Mounted folders appear instantly in the file explorer, support full-text search, ${quickSwitcher}, and all your plugins.`,
			cls: 'setting-item-description',
		});

		const tipBox = contentEl.createDiv({ cls: 'multifolder-tip-box' });
		tipBox.createEl('strong', { text: '💡 quick tip: ' });
		tipBox.appendText('After adding a mount, you can manage it from ');
		tipBox.createEl('strong', { text: `Settings, then ${pluginName}` });
		tipBox.appendText('. Per-mount options: read-only, custom ignore list, watcher tuning, and device-specific path overrides.');

		new Setting(contentEl)
			.addButton(btn => btn
				.setButtonText('Add my first mount')
				.setCta()
				.onClick(() => {
					this.close();
					this.onAddMount();
				}))
			.addButton(btn => btn
				.setButtonText('I\'ll explore on my own')
				.onClick(() => {
					this.close();
					this.onDismiss();
				}));
	}

	onClose(): void {
		this.contentEl.empty();
	}
}
