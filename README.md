# Bold APK (bapk)

A terminal UI for Alpine Linux's `apk` package manager, written in Rust with
[ratatui](https://ratatui.rs). A reimplementation of
[Bold Brew](https://github.com/Valkyrie00/bold-brew) (`bbrew`) for Alpine.

Requires apk-tools 3 (Alpine 3.23+): package data comes from `apk query --format json`.

## Usage

```sh
bapk             # browse all packages
bapk --version
```

## Keys

| Key | Action |
|-----|--------|
| `/` | Search (name and description) |
| `↑/↓` `j/k` `PgUp/PgDn` `g/G` | Navigate |
| `Esc` | Clear search / leave search |
| `f` / `o` / `l` | Toggle installed / upgradable / world (explicitly installed) |
| `m` / `c` | Toggle main / community repository |
| `s` | Cycle sort (None → Size → Name) |
| `i` / `u` / `r` | Install / upgrade / remove selected |
| `Ctrl+U` | Upgrade all |
| `v` | Vulnerability scan (Alpine secdb, cached 24h in `~/.cache/bapk`) |
| `?` | Help |
| `q` / `Ctrl+C` | Quit |

Table type tags: `[M]` main, `[C]` community, `[T]` testing, `[O]` other repository,
`[L]` installed locally but not available from any repository.

## Privileges

Package operations run as root when bapk is run as root. Otherwise bapk uses `doas`
(preferred) or `sudo`:

* if the tool can run without a password (`nopass`, or cached `persist`/sudo credentials),
  output streams into the Output panel;
* otherwise the TUI is suspended and the command runs in the terminal so you can enter your
  password, then you return to bapk.

The startup `apk update` index refresh only runs when no password is required.

## Development

Built test-first; all logic lives in the library crate and is unit tested, `main.rs` is
thin I/O wiring.

```sh
cargo test             # unit tests + integration tests against the local apk
cargo build --release  # target/release/bapk
```

| Module | Responsibility |
|--------|----------------|
| `version` | apk version comparison (matches `apk version -t`) |
| `models` | `Package`, `Repo`, `Filter`, `SortMode` |
| `catalog` | parse `apk query` JSON, merge available/installed/upgradable/world |
| `world` | `/etc/apk/world` parsing (marks explicitly installed packages) |
| `secdb` | Alpine security database lookups |
| `exec` | capture / line-streaming process execution |
| `apk` | privilege escalation, operations → apk argv, catalog loading |
| `app` | pure state machine: keys and events → state + `Command`s |
| `runtime` | executes commands (operations, secdb cache, scans) |
| `ui` | ratatui rendering (tested with `TestBackend`) |
| `cli` | argument parsing |
