//! Application state machine. Pure: key presses and background events mutate state and
//! may return a [`Command`] describing a side effect for the event loop to perform.

use std::collections::HashMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::apk::Operation;
use crate::models::{Filter, Package, SortMode};
use crate::secdb::Vulnerability;

pub const APP_NAME: &str = "Bold APK";
const MAX_OUTPUT_LINES: usize = 1000;

/// Severity of a status-bar notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub level: Level,
    pub text: String,
}

/// A pending confirmation dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub message: String,
    pub operations: Vec<Operation>,
    /// True when the "Confirm" button is highlighted, false for "Cancel".
    pub confirm_selected: bool,
}

/// Which part of the UI has input focus.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Normal,
    Search,
    Confirm(Confirm),
    Help,
}

/// Side effects requested by the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Quit,
    Run(Vec<Operation>),
    VulnScan(Box<Package>),
    /// Reload the package catalog from apk.
    Reload,
}

/// Events delivered from background work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    PackagesLoaded(Vec<Package>),
    OutputLine(String),
    Notify(Level, String),
    OperationStarted {
        index: usize,
        total: usize,
        operation: Operation,
    },
    OperationFinished {
        operation: Operation,
        error: Option<String>,
    },
    BatchFinished {
        total: usize,
        failed: usize,
    },
    VulnsScanned {
        name: String,
        result: Result<Vec<Vulnerability>, String>,
    },
}

/// A key hint in the legend bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegendEntry {
    pub key: &'static str,
    pub name: &'static str,
    pub active: bool,
}

pub struct App {
    pub packages: Vec<Package>,
    pub search: String,
    pub filter: Filter,
    pub sort: SortMode,
    pub mode: Mode,
    pub notification: Option<Notification>,
    pub output: Vec<String>,
    pub vulns: HashMap<String, Vec<Vulnerability>>,
    pub apk_version: String,
    pub busy: bool,
    /// Rows moved by PageUp/PageDown; updated by the UI to match the table height.
    pub page_size: usize,
    visible: Vec<usize>,
    selected: usize,
}

impl App {
    pub fn new(packages: Vec<Package>) -> App {
        let mut app = App {
            packages,
            search: String::new(),
            filter: Filter::None,
            sort: SortMode::None,
            mode: Mode::Normal,
            notification: None,
            output: Vec::new(),
            vulns: HashMap::new(),
            apk_version: "-".into(),
            busy: false,
            page_size: 10,
            visible: Vec::new(),
            selected: 0,
        };
        app.refresh(true);
        app
    }

    /// Packages currently shown in the table, in display order.
    pub fn visible(&self) -> Vec<&Package> {
        self.visible.iter().map(|&i| &self.packages[i]).collect()
    }

    /// Number of packages in the catalog.
    pub fn total(&self) -> usize {
        self.packages.len()
    }

    pub fn selected_index(&self) -> Option<usize> {
        (!self.visible.is_empty()).then_some(self.selected)
    }

    pub fn selected(&self) -> Option<&Package> {
        self.selected_index()
            .map(|i| &self.packages[self.visible[i]])
    }

    /// Recomputes the visible list. Keeps the selected package when `to_top` is false.
    fn refresh(&mut self, to_top: bool) {
        let previous = self.selected().map(|p| p.name.clone());
        self.refresh_keeping(if to_top { None } else { previous });
    }

    /// Recomputes the visible list, selecting `keep` if it is still visible.
    fn refresh_keeping(&mut self, keep: Option<String>) {
        let query = self.search.to_lowercase();
        let mut visible: Vec<usize> = self
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| self.filter.matches(p))
            .filter(|(_, p)| {
                query.is_empty()
                    || p.name.to_lowercase().contains(&query)
                    || p.description.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect();
        let pkgs = &self.packages;
        match self.sort {
            SortMode::None => {}
            SortMode::Size => {
                visible.sort_by(|&a, &b| pkgs[b].installed_size.cmp(&pkgs[a].installed_size))
            }
            SortMode::Name => {
                visible.sort_by_cached_key(|&i| pkgs[i].name.to_lowercase());
            }
        }
        self.visible = visible;
        self.selected = match keep {
            Some(name) => self
                .visible
                .iter()
                .position(|&i| self.packages[i].name == name)
                .unwrap_or(0),
            _ => 0,
        };
    }

    fn notify(&mut self, level: Level, text: impl Into<String>) {
        self.notification = Some(Notification {
            level,
            text: text.into(),
        });
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let max = self.visible.len() as isize - 1;
        self.selected = (self.selected as isize + delta).clamp(0, max) as usize;
    }

    fn handle_navigation(&mut self, code: KeyCode) -> bool {
        let page = self.page_size.max(1) as isize;
        match code {
            KeyCode::Down => self.move_selection(1),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(page),
            KeyCode::PageUp => self.move_selection(-page),
            KeyCode::Home => self.move_selection(isize::MIN / 2),
            KeyCode::End => self.move_selection(isize::MAX / 2),
            _ => return false,
        }
        true
    }

    fn toggle_filter(&mut self, filter: Filter) {
        self.filter = if self.filter == filter {
            Filter::None
        } else {
            filter
        };
        self.refresh(true);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Command> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Command::Quit);
        }
        match self.mode {
            Mode::Search => self.handle_search_key(key),
            Mode::Help => {
                self.mode = Mode::Normal;
                None
            }
            Mode::Confirm(_) => self.handle_confirm_key(key),
            Mode::Normal => self.handle_normal_key(key),
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> Option<Command> {
        let Mode::Confirm(confirm) = &mut self.mode else {
            return None;
        };
        let accept = match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
                confirm.confirm_selected = !confirm.confirm_selected;
                return None;
            }
            KeyCode::Enter => confirm.confirm_selected,
            KeyCode::Char('y') | KeyCode::Char('Y') => true,
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => false,
            _ => return None,
        };
        let Mode::Confirm(confirm) = std::mem::take(&mut self.mode) else {
            unreachable!()
        };
        if !accept {
            return None;
        }
        self.busy = true;
        self.output.clear();
        Some(Command::Run(confirm.operations))
    }

    fn ask(&mut self, message: String, operations: Vec<Operation>) {
        if self.busy {
            self.notify(Level::Warning, "Another operation is already running");
            return;
        }
        self.mode = Mode::Confirm(Confirm {
            message,
            operations,
            confirm_selected: true,
        });
    }

    fn ask_single(&mut self, action: &str, make: fn(String) -> Operation, require_installed: bool) {
        let Some(pkg) = self.selected() else {
            return;
        };
        let name = pkg.name.clone();
        if require_installed && !pkg.installed {
            self.notify(Level::Warning, format!("{name} is not installed"));
            return;
        }
        self.ask(
            format!("Are you sure you want to {action} the package: {name}?"),
            vec![make(name)],
        );
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> Option<Command> {
        if self.handle_navigation(key.code) {
            return None;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Backspace => {
                self.search.pop();
                self.refresh(true);
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search.push(c);
                self.refresh(true);
            }
            _ => {}
        }
        None
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> Option<Command> {
        if self.handle_navigation(key.code) {
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('g') => self.move_selection(isize::MIN / 2),
            KeyCode::Char('G') => self.move_selection(isize::MAX / 2),
            KeyCode::Char('/') => self.mode = Mode::Search,
            KeyCode::Char('f') => self.toggle_filter(Filter::Installed),
            KeyCode::Char('o') => self.toggle_filter(Filter::Upgradable),
            KeyCode::Char('l') => self.toggle_filter(Filter::World),
            KeyCode::Char('m') => self.toggle_filter(Filter::Main),
            KeyCode::Char('c') => self.toggle_filter(Filter::Community),
            KeyCode::Char('t') => self.toggle_filter(Filter::Tui),
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.refresh(false);
                self.notify(Level::Success, format!("Sort: {}", self.sort.label()));
            }
            KeyCode::Char('u') if ctrl => self.ask(
                "Are you sure you want to upgrade all packages?".into(),
                vec![Operation::UpgradeAll],
            ),
            // Other Ctrl combinations are unbound; don't let them act as plain letters.
            KeyCode::Char(_) if ctrl => {}
            KeyCode::Char('q') => return Some(Command::Quit),
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Esc => {
                self.search.clear();
                self.refresh(false);
            }
            KeyCode::Char('i') => self.ask_single("install", Operation::Install, false),
            KeyCode::Char('u') => self.ask_single("upgrade", Operation::Upgrade, true),
            KeyCode::Char('r') => self.ask_single("remove", Operation::Remove, true),
            KeyCode::Char('v') => {
                let pkg = self.selected()?.clone();
                self.notify(
                    Level::Warning,
                    format!("Scanning {} for vulnerabilities...", pkg.name),
                );
                return Some(Command::VulnScan(Box::new(pkg)));
            }
            _ => {}
        }
        None
    }

    fn push_output(&mut self, line: String) {
        self.output.push(line);
        if self.output.len() > MAX_OUTPUT_LINES {
            let excess = self.output.len() - MAX_OUTPUT_LINES;
            self.output.drain(..excess);
        }
    }

    pub fn handle_event(&mut self, event: AppEvent) -> Option<Command> {
        match event {
            AppEvent::PackagesLoaded(packages) => {
                let keep = self.selected().map(|p| p.name.clone());
                self.packages = packages;
                self.refresh_keeping(keep);
            }
            AppEvent::OutputLine(line) => self.push_output(line),
            AppEvent::Notify(level, text) => self.notify(level, text),
            AppEvent::OperationStarted {
                index,
                total,
                operation,
            } => {
                let what = format!("{} {}", operation.verb(), operation.subject());
                let progress = if total > 1 {
                    format!("[{index}/{total}] ")
                } else {
                    String::new()
                };
                self.notify(Level::Warning, format!("{progress}{what}..."));
                self.push_output(format!("==> {what}"));
            }
            AppEvent::OperationFinished { operation, error } => match error {
                None => {
                    let text = format!("{} {}", operation.past(), operation.subject());
                    self.push_output(format!("[SUCCESS] {text}"));
                    self.notify(Level::Success, text);
                }
                Some(err) => {
                    self.push_output(format!("[ERROR] {err}"));
                    self.notify(
                        Level::Error,
                        format!(
                            "Error {} {}",
                            operation.verb().to_lowercase(),
                            operation.subject()
                        ),
                    );
                }
            },
            AppEvent::BatchFinished { total, failed } => {
                self.busy = false;
                if total > 1 {
                    if failed > 0 {
                        self.notify(
                            Level::Warning,
                            format!("Completed! Processed {total} packages ({failed} failed)"),
                        );
                    } else {
                        self.notify(
                            Level::Success,
                            format!("Completed! Processed {total} packages"),
                        );
                    }
                }
                return Some(Command::Reload);
            }
            AppEvent::VulnsScanned { name, result } => match result {
                Ok(vulns) => {
                    match vulns.len() {
                        0 => {
                            self.notify(Level::Success, format!("{name}: no vulnerabilities found"))
                        }
                        1 => self.notify(Level::Error, format!("{name}: 1 vulnerability found")),
                        n => {
                            self.notify(Level::Error, format!("{name}: {n} vulnerabilities found"))
                        }
                    }
                    self.vulns.insert(name, vulns);
                }
                Err(err) => self.notify(Level::Error, format!("Vuln scan failed: {err}")),
            },
        }
        None
    }

    /// Label shown before the search input.
    pub fn search_label(&self) -> String {
        format!("Search ({}): ", self.filter.label())
    }

    /// Key hints for the legend bar.
    pub fn legend(&self) -> Vec<LegendEntry> {
        let mut entries = vec![
            ("/", "Search"),
            ("f", "Installed"),
            ("s", "Sort"),
            ("v", "Vuln Scan"),
            ("i", "Install"),
            ("u", "Upgrade"),
            ("r", "Remove"),
        ];
        entries.push(("?", "Help"));
        let active_key = match self.filter {
            Filter::Installed => Some("f"),
            _ => None,
        };
        entries
            .into_iter()
            .map(|(key, name)| LegendEntry {
                key,
                name,
                active: Some(key) == active_key,
            })
            .collect()
    }

    /// Header line text.
    pub fn header(&self) -> String {
        format!(
            "{APP_NAME} {} - {}",
            env!("CARGO_PKG_VERSION"),
            self.apk_version
        )
    }

    /// Package counter text.
    pub fn counter(&self) -> String {
        format!("Total: {} | Filtered: {}", self.total(), self.visible.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Repo;

    pub(crate) fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    pub(crate) fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    pub(crate) fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    pub(crate) fn pkg(name: &str) -> Package {
        Package {
            name: name.into(),
            version: "1.0-r0".into(),
            description: format!("{name} description"),
            repo: Repo::Main,
            ..Default::default()
        }
    }

    /// curl (installed, upgradable, explicit, 300B), bash (installed, 100B),
    /// zsh (community, 200B), git (not installed, 50B)
    pub(crate) fn sample() -> Vec<Package> {
        let mut curl = pkg("curl");
        curl.installed = true;
        curl.upgradable = true;
        curl.explicit = true;
        curl.installed_size = 300;
        curl.installed_version = Some("0.9-r0".into());
        let mut bash = pkg("bash");
        bash.installed = true;
        bash.installed_size = 100;
        bash.installed_version = Some("1.0-r0".into());
        bash.description = "The GNU Bourne Again shell".into();
        let mut zsh = pkg("zsh");
        zsh.repo = Repo::Community;
        zsh.installed_size = 200;
        let mut git = pkg("git");
        git.installed_size = 50;
        vec![curl, bash, zsh, git]
    }

    pub(crate) fn names(app: &App) -> Vec<String> {
        app.visible().iter().map(|p| p.name.clone()).collect()
    }

    fn app() -> App {
        App::new(sample())
    }

    // ---- navigation -------------------------------------------------------

    #[test]
    fn starts_with_all_packages_and_first_selected() {
        let a = app();
        assert_eq!(names(&a), vec!["curl", "bash", "zsh", "git"]);
        assert_eq!(a.selected_index(), Some(0));
        assert_eq!(a.selected().unwrap().name, "curl");
        assert_eq!(a.total(), 4);
    }

    #[test]
    fn empty_app_has_no_selection() {
        let a = App::new(vec![]);
        assert_eq!(a.selected_index(), None);
        assert!(a.selected().is_none());
    }

    #[test]
    fn down_and_up_move_selection_with_bounds() {
        let mut a = app();
        a.handle_key(key(KeyCode::Down));
        a.handle_key(ch('j'));
        assert_eq!(a.selected().unwrap().name, "zsh");
        a.handle_key(ch('j'));
        a.handle_key(ch('j'));
        assert_eq!(a.selected().unwrap().name, "git");
        a.handle_key(key(KeyCode::Up));
        assert_eq!(a.selected().unwrap().name, "zsh");
        a.handle_key(ch('k'));
        a.handle_key(ch('k'));
        a.handle_key(ch('k'));
        assert_eq!(a.selected().unwrap().name, "curl");
    }

    #[test]
    fn home_end_and_paging() {
        let mut a = app();
        a.page_size = 2;
        a.handle_key(key(KeyCode::End));
        assert_eq!(a.selected_index(), Some(3));
        a.handle_key(key(KeyCode::Home));
        assert_eq!(a.selected_index(), Some(0));
        a.handle_key(key(KeyCode::PageDown));
        assert_eq!(a.selected_index(), Some(2));
        a.handle_key(key(KeyCode::PageDown));
        assert_eq!(a.selected_index(), Some(3));
        a.handle_key(key(KeyCode::PageUp));
        assert_eq!(a.selected_index(), Some(1));
        a.handle_key(ch('G'));
        assert_eq!(a.selected_index(), Some(3));
        a.handle_key(ch('g'));
        assert_eq!(a.selected_index(), Some(0));
    }

    // ---- filters ----------------------------------------------------------

    #[test]
    fn filter_keys_toggle() {
        let mut a = app();
        a.handle_key(ch('f'));
        assert_eq!(a.filter, Filter::Installed);
        assert_eq!(names(&a), vec!["curl", "bash"]);
        a.handle_key(ch('f'));
        assert_eq!(a.filter, Filter::None);
        assert_eq!(names(&a).len(), 4);
    }

    #[test]
    fn each_filter_key() {
        let mut a = app();
        a.handle_key(ch('o'));
        assert_eq!(
            (a.filter, names(&a)),
            (Filter::Upgradable, vec!["curl".to_string()])
        );
        a.handle_key(ch('l'));
        assert_eq!(
            (a.filter, names(&a)),
            (Filter::World, vec!["curl".to_string()])
        );
        a.handle_key(ch('c'));
        assert_eq!(
            (a.filter, names(&a)),
            (Filter::Community, vec!["zsh".to_string()])
        );
        a.handle_key(ch('m'));
        assert_eq!(a.filter, Filter::Main);
        assert_eq!(names(&a), vec!["curl", "bash", "git"]);
    }

    #[test]
    fn tui_filter_key() {
        let mut packages = sample();
        packages[2].tui = true;
        let mut a = App::new(packages);
        a.handle_key(ch('t'));
        assert_eq!(
            (a.filter, names(&a)),
            (Filter::Tui, vec!["zsh".to_string()])
        );
        assert_eq!(a.search_label(), "Search (TUI): ");
        a.handle_key(ch('t'));
        assert_eq!(a.filter, Filter::None);
    }

    #[test]
    fn filtering_resets_selection_to_top() {
        let mut a = app();
        a.handle_key(key(KeyCode::End));
        a.handle_key(ch('f'));
        assert_eq!(a.selected_index(), Some(0));
    }

    #[test]
    fn filter_with_no_matches_clears_selection() {
        let mut a = App::new(vec![pkg("x")]);
        a.handle_key(ch('f'));
        assert!(a.visible().is_empty());
        assert_eq!(a.selected_index(), None);
        a.handle_key(ch('j'));
        assert_eq!(a.selected_index(), None);
    }

    // ---- sorting ----------------------------------------------------------

    #[test]
    fn sort_cycles_size_name_none() {
        let mut a = app();
        a.handle_key(ch('s'));
        assert_eq!(a.sort, SortMode::Size);
        assert_eq!(names(&a), vec!["curl", "zsh", "bash", "git"]);
        assert_eq!(a.notification.as_ref().unwrap().text, "Sort: Size");
        a.handle_key(ch('s'));
        assert_eq!(a.sort, SortMode::Name);
        assert_eq!(names(&a), vec!["bash", "curl", "git", "zsh"]);
        a.handle_key(ch('s'));
        assert_eq!(a.sort, SortMode::None);
        assert_eq!(names(&a), vec!["curl", "bash", "zsh", "git"]);
    }

    #[test]
    fn name_sort_is_case_insensitive() {
        let mut a = App::new(vec![pkg("b"), pkg("A"), pkg("c")]);
        a.handle_key(ch('s'));
        a.handle_key(ch('s'));
        assert_eq!(names(&a), vec!["A", "b", "c"]);
    }

    #[test]
    fn sort_keeps_selected_package() {
        let mut a = app();
        a.handle_key(ch('j')); // bash
        a.handle_key(ch('s')); // size: curl zsh bash git
        assert_eq!(a.selected().unwrap().name, "bash");
    }

    // ---- search -----------------------------------------------------------

    #[test]
    fn slash_enters_search_mode_and_typing_filters() {
        let mut a = app();
        a.handle_key(ch('/'));
        assert_eq!(a.mode, Mode::Search);
        a.handle_key(ch('s'));
        a.handle_key(ch('h'));
        assert_eq!(a.search, "sh");
        // matches name (bash, zsh) — not a sort keypress
        assert_eq!(a.sort, SortMode::None);
        assert_eq!(names(&a), vec!["bash", "zsh"]);
    }

    #[test]
    fn search_matches_description_case_insensitively() {
        let mut a = app();
        a.handle_key(ch('/'));
        for c in "BOURNE".chars() {
            a.handle_key(ch(c));
        }
        assert_eq!(names(&a), vec!["bash"]);
    }

    #[test]
    fn search_backspace_and_exit_keep_query() {
        let mut a = app();
        a.handle_key(ch('/'));
        a.handle_key(ch('z'));
        a.handle_key(ch('q'));
        assert!(names(&a).is_empty());
        a.handle_key(key(KeyCode::Backspace));
        assert_eq!(names(&a), vec!["zsh"]);
        a.handle_key(key(KeyCode::Enter));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(names(&a), vec!["zsh"]);
        a.handle_key(ch('/'));
        a.handle_key(key(KeyCode::Esc));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.search, "z");
    }

    #[test]
    fn search_combines_with_filter() {
        let mut a = app();
        a.handle_key(ch('f'));
        a.handle_key(ch('/'));
        a.handle_key(ch('s'));
        a.handle_key(ch('h'));
        assert_eq!(names(&a), vec!["bash"]);
    }

    #[test]
    fn search_mode_ignores_ctrl_shortcuts_but_allows_navigation() {
        let mut a = app();
        a.handle_key(ch('/'));
        assert_eq!(a.handle_key(ctrl('u')), None);
        a.handle_key(key(KeyCode::Down));
        assert_eq!(a.selected_index(), Some(1));
    }

    // ---- quit / help ------------------------------------------------------

    #[test]
    fn q_and_ctrl_c_quit() {
        assert_eq!(app().handle_key(ch('q')), Some(Command::Quit));
        assert_eq!(app().handle_key(ctrl('c')), Some(Command::Quit));
        let mut a = app();
        a.handle_key(ch('/'));
        assert_eq!(a.handle_key(ctrl('c')), Some(Command::Quit));
    }

    #[test]
    fn help_opens_and_any_key_closes() {
        let mut a = app();
        a.handle_key(ch('?'));
        assert_eq!(a.mode, Mode::Help);
        assert_eq!(a.handle_key(ch('q')), None);
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn esc_in_normal_mode_clears_search() {
        let mut a = app();
        a.handle_key(ch('/'));
        a.handle_key(ch('z'));
        a.handle_key(key(KeyCode::Enter));
        a.handle_key(key(KeyCode::Esc));
        assert_eq!(a.search, "");
        assert_eq!(names(&a).len(), 4);
    }

    // ---- single operations ------------------------------------------------

    fn confirm(a: &App) -> &Confirm {
        match &a.mode {
            Mode::Confirm(c) => c,
            other => panic!("expected confirm mode, got {other:?}"),
        }
    }

    #[test]
    fn install_asks_for_confirmation() {
        let mut a = app();
        a.handle_key(ch('G')); // git
        assert_eq!(a.handle_key(ch('i')), None);
        let c = confirm(&a);
        assert_eq!(
            c.message,
            "Are you sure you want to install the package: git?"
        );
        assert_eq!(c.operations, vec![Operation::Install("git".into())]);
        assert!(c.confirm_selected);
    }

    #[test]
    fn confirming_runs_operation_and_marks_busy() {
        let mut a = app();
        a.output.push("old output".into());
        a.handle_key(ch('i'));
        assert_eq!(
            a.handle_key(key(KeyCode::Enter)),
            Some(Command::Run(vec![Operation::Install("curl".into())]))
        );
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.busy);
        assert!(a.output.is_empty());
    }

    #[test]
    fn y_confirms_and_n_or_esc_cancels() {
        let mut a = app();
        a.handle_key(ch('i'));
        assert!(matches!(a.handle_key(ch('y')), Some(Command::Run(_))));
        let mut a = app();
        a.handle_key(ch('i'));
        assert_eq!(a.handle_key(ch('n')), None);
        assert_eq!(a.mode, Mode::Normal);
        let mut a = app();
        a.handle_key(ch('i'));
        assert_eq!(a.handle_key(key(KeyCode::Esc)), None);
        assert_eq!(a.mode, Mode::Normal);
        assert!(!a.busy);
    }

    #[test]
    fn toggling_to_cancel_button_then_enter_cancels() {
        let mut a = app();
        a.handle_key(ch('i'));
        a.handle_key(key(KeyCode::Right));
        assert!(!confirm(&a).confirm_selected);
        a.handle_key(key(KeyCode::Tab));
        assert!(confirm(&a).confirm_selected);
        a.handle_key(key(KeyCode::Left));
        assert!(!confirm(&a).confirm_selected);
        assert_eq!(a.handle_key(key(KeyCode::Enter)), None);
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn confirm_mode_swallows_other_keys() {
        let mut a = app();
        a.handle_key(ch('i'));
        assert_eq!(a.handle_key(ch('q')), None);
        assert!(matches!(a.mode, Mode::Confirm(_)));
    }

    #[test]
    fn upgrade_and_remove_selected() {
        let mut a = app();
        a.handle_key(ch('u'));
        assert_eq!(
            confirm(&a).message,
            "Are you sure you want to upgrade the package: curl?"
        );
        assert_eq!(
            confirm(&a).operations,
            vec![Operation::Upgrade("curl".into())]
        );
        let mut a = app();
        a.handle_key(ch('r'));
        assert_eq!(
            confirm(&a).message,
            "Are you sure you want to remove the package: curl?"
        );
        assert_eq!(
            confirm(&a).operations,
            vec![Operation::Remove("curl".into())]
        );
    }

    #[test]
    fn upgrade_or_remove_of_uninstalled_package_warns() {
        let mut a = app();
        a.handle_key(ch('G')); // git: not installed
        a.handle_key(ch('u'));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.notification.as_ref().unwrap().level, Level::Warning);
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "git is not installed"
        );
        a.handle_key(ch('r'));
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn operations_need_a_selection() {
        let mut a = App::new(vec![]);
        a.handle_key(ch('i'));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(a.handle_key(ch('v')), None);
    }

    #[test]
    fn upgrade_all_with_ctrl_u() {
        let mut a = app();
        a.handle_key(ctrl('u'));
        assert_eq!(
            confirm(&a).message,
            "Are you sure you want to upgrade all packages?"
        );
        assert_eq!(confirm(&a).operations, vec![Operation::UpgradeAll]);
    }

    #[test]
    fn busy_blocks_new_operations() {
        let mut a = app();
        a.busy = true;
        a.handle_key(ch('i'));
        assert_eq!(a.mode, Mode::Normal);
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "Another operation is already running"
        );
        a.handle_key(ctrl('u'));
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn ctrl_a_and_ctrl_r_do_nothing() {
        let mut a = app();
        a.handle_key(ctrl('a'));
        a.handle_key(ctrl('r'));
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.notification.is_none());
    }

    // ---- vuln scan -----------------------------------------------

    #[test]
    fn e_key_does_nothing() {
        let mut a = app();
        assert_eq!(a.handle_key(ch('e')), None);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.notification.is_none());
    }

    #[test]
    fn vuln_scan_returns_command_for_selected() {
        let mut a = app();
        let cmd = a.handle_key(ch('v'));
        assert_eq!(cmd, Some(Command::VulnScan(Box::new(sample()[0].clone()))));
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "Scanning curl for vulnerabilities..."
        );
    }

    // ---- background events ------------------------------------------------

    #[test]
    fn packages_loaded_replaces_and_keeps_selection() {
        let mut a = app();
        a.handle_key(ch('j')); // bash
        let mut pkgs = sample();
        pkgs.insert(0, pkg("aaa"));
        assert_eq!(a.handle_event(AppEvent::PackagesLoaded(pkgs)), None);
        assert_eq!(a.visible().len(), 5);
        assert_eq!(a.selected().unwrap().name, "bash");
    }

    #[test]
    fn output_lines_append_and_are_capped() {
        let mut a = app();
        for i in 0..1205 {
            a.handle_event(AppEvent::OutputLine(format!("line {i}")));
        }
        assert_eq!(a.output.len(), 1000);
        assert_eq!(a.output.last().unwrap(), "line 1204");
    }

    #[test]
    fn notify_event_sets_notification() {
        let mut a = app();
        a.handle_event(AppEvent::Notify(Level::Error, "bad".into()));
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Error,
                text: "bad".into()
            })
        );
    }

    #[test]
    fn operation_progress_messages() {
        let mut a = app();
        let op = Operation::Install("git".into());
        a.handle_event(AppEvent::OperationStarted {
            index: 1,
            total: 1,
            operation: op.clone(),
        });
        assert_eq!(a.notification.as_ref().unwrap().text, "Installing git...");
        assert_eq!(a.output.last().unwrap(), "==> Installing git");
        a.handle_event(AppEvent::OperationStarted {
            index: 2,
            total: 3,
            operation: op.clone(),
        });
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "[2/3] Installing git..."
        );
        a.handle_event(AppEvent::OperationFinished {
            operation: op.clone(),
            error: None,
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Success,
                text: "Installed git".into()
            })
        );
        assert_eq!(a.output.last().unwrap(), "[SUCCESS] Installed git");
        a.handle_event(AppEvent::OperationFinished {
            operation: op,
            error: Some("exit 1".into()),
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Error,
                text: "Error installing git".into()
            })
        );
        assert_eq!(a.output.last().unwrap(), "[ERROR] exit 1");
    }

    #[test]
    fn batch_finished_clears_busy_and_requests_reload() {
        let mut a = app();
        a.busy = true;
        a.handle_event(AppEvent::OperationFinished {
            operation: Operation::UpgradeAll,
            error: None,
        });
        assert_eq!(
            a.handle_event(AppEvent::BatchFinished {
                total: 1,
                failed: 0
            }),
            Some(Command::Reload)
        );
        assert!(!a.busy);
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "Upgraded all packages"
        );
        a.handle_event(AppEvent::BatchFinished {
            total: 3,
            failed: 1,
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Warning,
                text: "Completed! Processed 3 packages (1 failed)".into()
            })
        );
        a.handle_event(AppEvent::BatchFinished {
            total: 2,
            failed: 0,
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Success,
                text: "Completed! Processed 2 packages".into()
            })
        );
    }

    #[test]
    fn vulns_scanned_results() {
        let mut a = app();
        a.handle_event(AppEvent::VulnsScanned {
            name: "curl".into(),
            result: Ok(vec![]),
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Success,
                text: "curl: no vulnerabilities found".into()
            })
        );
        assert_eq!(a.vulns.get("curl"), Some(&vec![]));
        let v = Vulnerability {
            id: "CVE-1".into(),
            fixed_in: "2-r0".into(),
        };
        a.handle_event(AppEvent::VulnsScanned {
            name: "bash".into(),
            result: Ok(vec![v.clone()]),
        });
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "bash: 1 vulnerability found"
        );
        assert_eq!(a.notification.as_ref().unwrap().level, Level::Error);
        a.handle_event(AppEvent::VulnsScanned {
            name: "bash".into(),
            result: Ok(vec![v.clone(), v]),
        });
        assert_eq!(
            a.notification.as_ref().unwrap().text,
            "bash: 2 vulnerabilities found"
        );
        a.handle_event(AppEvent::VulnsScanned {
            name: "x".into(),
            result: Err("offline".into()),
        });
        assert_eq!(
            a.notification,
            Some(Notification {
                level: Level::Error,
                text: "Vuln scan failed: offline".into()
            })
        );
    }

    // ---- labels -----------------------------------------------------------

    #[test]
    fn search_labels() {
        let mut a = app();
        assert_eq!(a.search_label(), "Search (All): ");
        a.handle_key(ch('f'));
        assert_eq!(a.search_label(), "Search (Installed): ");
    }

    #[test]
    fn legend_entries_and_active_filter() {
        let mut a = app();
        let keys: Vec<&str> = a.legend().iter().map(|e| e.key).collect();
        assert_eq!(keys, vec!["/", "f", "s", "v", "i", "u", "r", "?"]);
        assert!(a.legend().iter().all(|e| !e.active));
        a.handle_key(ch('f'));
        let active: Vec<&str> = a
            .legend()
            .iter()
            .filter(|e| e.active)
            .map(|e| e.key)
            .collect();
        assert_eq!(active, vec!["f"]);
    }

    #[test]
    fn header_and_counter() {
        let mut a = app();
        a.apk_version = "apk-tools 3.0.8-r0".into();
        assert_eq!(
            a.header(),
            format!(
                "Bold APK {} - apk-tools 3.0.8-r0",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(a.counter(), "Total: 4 | Filtered: 4");
        a.handle_key(ch('f'));
        assert_eq!(a.counter(), "Total: 4 | Filtered: 2");
    }
}
