# SSHMenu

A terminal-based session manager for SSH connections, supporting two-step navigation and search.

## Features
- Two-step UI: Select project, then server (when no filter is used)
- Flat filtered list: Search servers by name or description using a command-line parameter
- Custom SSH commands per server or global command template
- Inplace update

## Usage
### Installation

1. **Download the latest release:**
   - Go to the [GitHub Releases page](https://github.com/vorn003/session-manager/releases)
   - Download the `sshmenu` binary for your platform (e.g., `sshmenu-linux-amd64`, etc.)
   - Make it executable if needed:
     ```
     chmod +x sshmenu
     ```
   - (Optional) Move the binary to your PATH:
     ```
     sudo mv sshmenu /usr/local/bin/
     ```

2. **Configuration file location:**
   - By default, SSHMenu will look for the configuration file at `~/.config/sshmenu/sshmenu.yaml`.
   - If that file does not exist, it will use `sshmenu.yaml` in the same directory as the binary.
   - You can copy or move your configuration file to either location as needed.

### Run
#### Two-step UI (project → server)
```
./sshmenu
```
#### Flat filtered list
```
./sshmenu <search>
# Example:
./sshmenu App
```

## Config File: sshmenu.yaml
Example:
```yaml
global_command: pamssh {server}
# exit_on_disconnect: false  # Set to false to return to SSHMenu after disconnecting instead of exiting
projects:
  - name: Customer A
    servers:
      - name: server1
        description: App A Server 1
      - name: server2
        description: App B Server 2
  - name: Customer B
    servers:
      - name: server3
        description: App C Server 3
        command: ssh server3 -p 2222
```

### Config Options
| Option               | Type   | Default | Description                                                                 |
|----------------------|--------|---------|-----------------------------------------------------------------------------|
| `global_command`     | string | —       | Command template for servers without a custom command. Use `{server}` as placeholder. |
| `exit_on_disconnect` | bool   | `true`  | When `true`, exit sshmenu immediately after an SSH session ends (two-layer mode). When `false`, return to the server selection menu. |

### Per-Server Options
| Option        | Type   | Description                                          |
|---------------|--------|------------------------------------------------------|
| `name`        | string | Server hostname or identifier (used in `{server}`).  |
| `description` | string | Human-readable label shown in the menu.              |
| `command`     | string | Override the global command for this server.         |

## Navigation
- Use ↑/↓ to navigate
- Enter to select

## Command-line options
| Option              | Description                              |
|---------------------|------------------------------------------|
| sshmenu [search]    | Launch menu, optionally filter servers    |
| --help              | Show help message                        |
| --update            | Update to latest release from GitHub      |
| --version           | Show version                             |

## Build yourself
```
go build -o sshmenu sshmenu.go
```

**Build without linking to libc (static, pure-Go build)**

To produce a Linux binary that does not link against the system `libc` (avoid cgo), build with `CGO_ENABLED=0`. This uses the pure-Go resolver and avoids depending on system C libraries.

Example (Linux amd64):

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags netgo -ldflags "-s -w" -o sshmenu ./...
```

Or use the provided Makefile target:

```
make build
```

Notes:
- `CGO_ENABLED=0` disables cgo so the binary will not be linked against `libc`.
- `-tags netgo` forces the pure-Go DNS resolver (avoid cgo-based name resolution).
- `-ldflags "-s -w"` strips debug info to reduce binary size.


## License
MIT
