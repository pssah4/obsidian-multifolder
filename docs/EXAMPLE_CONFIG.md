# Example Multifolder Configuration

This file demonstrates how to configure mount points for the Multifolder plugin.
Mount points are configured through the Obsidian settings UI, but this example shows the data structure.

## Configuration Structure

```json
{
  "mountPoints": [
    {
      "virtualPath": "Projects/Work",
      "realPath": "/Users/username/Documents/WorkProjects",
      "enabled": true
    },
    {
      "virtualPath": "References/Research",
      "realPath": "/Users/username/Dropbox/ResearchPapers",
      "enabled": true
    },
    {
      "virtualPath": "Archive/Old",
      "realPath": "/Volumes/Backup/OldNotes",
      "enabled": false
    }
  ]
}
```

## Field Descriptions

- **virtualPath**: The path as it appears in your Obsidian vault (relative to vault root)
- **realPath**: The actual filesystem path that the virtual path maps to
- **enabled**: Whether this mount point is currently active

## Usage Notes

1. **Virtual paths** should use forward slashes (/) regardless of OS
2. **Real paths** should use OS-appropriate path separators
3. Virtual paths must be unique within the vault
4. Real paths must exist on the filesystem before mounting
5. Disabled mount points are preserved but not active

## Security Considerations

- Only mount directories you trust
- Be careful with mount points that have write access
- Avoid mounting system directories
- Consider using read-only mounts for reference material

## Best Practices

1. **Organize logically**: Group related external folders under a common virtual path prefix
2. **Use descriptive names**: Make virtual paths self-explanatory
3. **Document your setup**: Keep track of what you've mounted and why
4. **Start small**: Test with one or two mount points before expanding
5. **Backup regularly**: While files stay in their original locations, backup your mount configuration

## Troubleshooting

- **Mount point not visible**: Check that the real path exists and is accessible
- **Permission errors**: Ensure you have read/write access to the real path
- **Path conflicts**: Virtual paths cannot overlap with existing vault folders
- **Performance issues**: Mounting very large directories may impact performance

## Future Enhancements

The virtual filesystem adapter will add:
- Automatic conflict resolution
- Bidirectional synchronization
- Advanced filtering options
- Mount point templates
- Backup and restore for mount configurations
