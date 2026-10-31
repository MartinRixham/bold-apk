//! Rendering with ratatui.

pub mod details;
pub mod format;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};

use crate::app::{App, Confirm, Level, Mode};
use crate::models::SortMode;
use format::{human_size, truncate};

const ORANGE: Color = Color::Indexed(208);
const TITLE: Color = Color::Magenta;

/// Persistent rendering state (e.g. table scroll offset).
#[derive(Default)]
pub struct Ui {
    offset: usize,
}

impl Ui {
    /// Renders the whole application. Updates `app.page_size` to the table height.
    pub fn draw(&mut self, frame: &mut Frame, app: &mut App) {
        let area = frame.area();
        let [header, main, output, legend] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(7),
            Constraint::Length(1),
        ])
        .areas(area);
        draw_header(frame, header, app);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(75), Constraint::Percentage(25)])
                .areas(main);
        self.draw_left(frame, left, app);
        draw_details(frame, right, app);
        draw_output(frame, output, app);
        draw_legend(frame, legend, app);
        match &app.mode {
            Mode::Help => draw_help(frame, area),
            Mode::Confirm(confirm) => draw_confirm(frame, area, confirm),
            _ => {}
        }
    }

    fn draw_left(&mut self, frame: &mut Frame, area: Rect, app: &mut App) {
        let block = Block::new().borders(Borders::TOP | Borders::BOTTOM);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let [search, table] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
        let [field, counter] =
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
                .areas(search);
        let label = app.search_label();
        let query = Span::styled(
            app.search.clone(),
            Style::new().add_modifier(Modifier::ITALIC | Modifier::UNDERLINED),
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(label.clone(), Style::new().fg(TITLE)),
                query,
            ])),
            field,
        );
        frame.render_widget(
            Paragraph::new(app.counter()).alignment(Alignment::Right),
            counter,
        );
        if app.mode == Mode::Search {
            let x = field.x + (label.chars().count() + app.search.chars().count()) as u16;
            frame.set_cursor_position(Position::new(
                x.min(field.right().saturating_sub(1)),
                field.y,
            ));
        }
        self.draw_table(frame, table, app);
    }

    fn draw_table(&mut self, frame: &mut Frame, area: Rect, app: &mut App) {
        let height = area.height.saturating_sub(1) as usize;
        app.page_size = height.max(1);
        let visible = app.visible();
        let selected = app.selected_index();
        if let Some(sel) = selected {
            if sel < self.offset {
                self.offset = sel;
            } else if height > 0 && sel >= self.offset + height {
                self.offset = sel + 1 - height;
            }
        }
        self.offset = self.offset.min(visible.len().saturating_sub(height.max(1)));

        let mut headers = ["Type", "Name", "Version", "Description", "Size"].map(String::from);
        match app.sort {
            SortMode::Name => headers[1].push_str(" ▼"),
            SortMode::Size => headers[4].push_str(" ▼"),
            SortMode::None => {}
        }
        let window = visible.iter().skip(self.offset).take(height);
        let name_width = visible
            .iter()
            .map(|p| p.name.chars().count())
            .max()
            .unwrap_or(4)
            .clamp(6, 32);
        let rows: Vec<Row> = window
            .map(|p| {
                let name_style = if p.installed {
                    Style::new().fg(Color::Green)
                } else {
                    Style::new()
                };
                let version_style = if p.installed && p.upgradable {
                    Style::new().fg(ORANGE)
                } else {
                    Style::new()
                };
                Row::new(vec![
                    Cell::from(p.repo.tag()),
                    Cell::from(Span::styled(truncate(&p.name, name_width), name_style)),
                    Cell::from(Span::styled(truncate(&p.version, 15), version_style)),
                    Cell::from(p.description.clone()),
                    Cell::from(
                        Line::from(human_size(p.installed_size)).alignment(Alignment::Right),
                    ),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(name_width as u16),
                Constraint::Length(15),
                Constraint::Fill(1),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(headers).style(Style::new().fg(Color::Blue)))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        let mut state = TableState::default().with_selected(selected.map(|s| s - self.offset));
        frame.render_stateful_widget(table, area, &mut state);
    }
}

fn level_color(level: Level) -> Color {
    match level {
        Level::Success => Color::Green,
        Level::Warning => Color::Yellow,
        Level::Error => Color::Red,
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    frame.render_widget(Paragraph::new(format!(" {}", app.header())), left);
    if let Some(n) = &app.notification {
        frame.render_widget(
            Paragraph::new(format!(" {} ", n.text))
                .style(Style::new().fg(level_color(n.level)))
                .alignment(Alignment::Right),
            right,
        );
    }
}

fn draw_details(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::new()
        .borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM)
        .title(Span::styled(" Details ", Style::new().fg(TITLE)));
    let pkg = app.selected();
    let vulns = pkg.and_then(|p| app.vulns.get(&p.name));
    let lines = details::details_lines(pkg, vulns);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_output(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(Span::styled(" Output ", Style::new().fg(TITLE)));
    let height = block.inner(area).height as usize;
    let start = app.output.len().saturating_sub(height);
    let lines: Vec<Line> = app.output[start..]
        .iter()
        .map(|l| Line::from(l.as_str()))
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_legend(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();
    for (i, entry) in app.legend().into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" | "));
        }
        let style = if entry.active {
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        spans.push(Span::styled(
            format!("[{}] {}", entry.key, entry.name),
            style,
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Center),
        area,
    );
}

/// A rectangle of the given size centered in `area`, clamped to fit.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

fn help_lines() -> Vec<Line<'static>> {
    let section = |t: &'static str| {
        Line::from(Span::styled(
            t,
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        ))
    };
    let key = |k: &'static str, d: &'static str| {
        Line::from(vec![
            Span::styled(format!("  {k:<12}"), Style::new().fg(Color::Yellow)),
            Span::raw(d),
        ])
    };
    let mut lines = vec![
        section("NAVIGATION"),
        key("↑/↓, j/k", "Navigate list"),
        key("PgUp/PgDn", "Page up/down"),
        key("g/G", "Top/bottom"),
        key("/", "Focus search"),
        key("Esc", "Clear search / back"),
        key("q", "Quit"),
        Line::default(),
        section("FILTERS"),
        key("f", "Toggle installed"),
        key("o", "Toggle upgradable"),
        key("l", "Toggle world (explicit)"),
        key("m", "Toggle main repository"),
        key("c", "Toggle community repository"),
        key("t", "Toggle TUI applications"),
        key("s", "Cycle sort mode"),
        Line::default(),
        section("ACTIONS"),
        key("i", "Install selected"),
        key("u", "Upgrade selected"),
        key("r", "Remove selected"),
        key("v", "Vulnerability scan"),
        key("Ctrl+U", "Upgrade all"),
    ];
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Press any key to close",
        Style::new().add_modifier(Modifier::DIM),
    )));
    lines
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let lines = help_lines();
    let popup = centered(area, 55, lines.len() as u16 + 4);
    frame.render_widget(Clear, popup);
    let block = Block::bordered()
        .title(" Help ")
        .title_alignment(Alignment::Center);
    frame.render_widget(
        Paragraph::new(lines).block(block.padding(ratatui::widgets::Padding::horizontal(1))),
        popup,
    );
}

fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm) {
    let width = 60u16;
    let text_width = width.saturating_sub(4).max(1) as usize;
    let message_lines: usize = confirm
        .message
        .lines()
        .map(|l| l.chars().count().div_ceil(text_width).max(1))
        .sum();
    let popup = centered(area, width, message_lines as u16 + 6);
    frame.render_widget(Clear, popup);
    let button = |label: &'static str, active: bool| {
        let style = if active {
            Style::new()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        Span::styled(label, style)
    };
    let mut lines: Vec<Line> = confirm
        .message
        .lines()
        .map(|l| Line::from(l.to_string()))
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(vec![
        button("  Confirm  ", confirm.confirm_selected),
        Span::raw("   "),
        button("  Cancel  ", !confirm.confirm_selected),
    ]));
    let block = Block::bordered().padding(ratatui::widgets::Padding::uniform(1));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppEvent, Level};
    use crate::models::{Package, Repo};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::style::Color;

    fn pkg(name: &str, installed: bool) -> Package {
        Package {
            name: name.into(),
            version: "1.0-r0".into(),
            description: format!("{name} description"),
            repo: Repo::Main,
            installed,
            installed_size: 2048,
            ..Default::default()
        }
    }

    fn sample() -> Vec<Package> {
        let mut zsh = pkg("zsh", false);
        zsh.repo = Repo::Community;
        vec![pkg("curl", true), pkg("bash", false), zsh]
    }

    fn render(app: &mut App, ui: &mut Ui, w: u16, h: u16) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| ui.draw(f, app)).unwrap();
        terminal
    }

    fn screen(t: &Terminal<TestBackend>) -> String {
        let buf = t.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn find(t: &Terminal<TestBackend>, needle: &str) -> Option<(u16, u16)> {
        screen(t).lines().enumerate().find_map(|(y, line)| {
            line.find(needle)
                .map(|byte| (line[..byte].chars().count() as u16, y as u16))
        })
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn renders_main_layout() {
        let mut app = App::new(sample());
        app.apk_version = "apk-tools 3.0.8-r0".into();
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        for expected in [
            "Bold APK",
            "apk-tools 3.0.8-r0",
            "Search (All):",
            "Total: 3 | Filtered: 3",
            "Type",
            "Name",
            "Version",
            "Description",
            "Size",
            "[M]",
            "[C]",
            "curl",
            "bash description",
            "2.0 KiB",
            "Details",
            "Output",
            "[/] Search",
            "[?] Help",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
    }

    #[test]
    fn details_show_selected_package() {
        let mut app = App::new(sample());
        app.handle_key(key('j'));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 50));
        assert!(s.contains("• Status: Not installed"), "{s}");
        assert!(s.contains("bash description"));
    }

    #[test]
    fn shows_search_query_and_notification() {
        let mut app = App::new(sample());
        app.handle_key(key('/'));
        app.handle_key(key('z'));
        app.handle_event(AppEvent::Notify(Level::Success, "All good".into()));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(s.contains("Search (All): z"), "{s}");
        assert!(s.contains("All good"));
        assert!(s.contains("Total: 3 | Filtered: 1"));
    }

    #[test]
    fn shows_sort_indicator() {
        let mut app = App::new(sample());
        app.handle_key(key('s'));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(s.contains("Size ▼"), "{s}");
        app.handle_key(key('s'));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(s.contains("Name ▼"), "{s}");
    }

    #[test]
    fn shows_output_lines() {
        let mut app = App::new(sample());
        app.handle_event(AppEvent::OutputLine("(1/1) Installing curl".into()));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(s.contains("(1/1) Installing curl"), "{s}");
    }

    #[test]
    fn output_panel_follows_latest_lines() {
        let mut app = App::new(sample());
        for i in 0..50 {
            app.handle_event(AppEvent::OutputLine(format!("output line {i:02}")));
        }
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(s.contains("output line 49"), "{s}");
        assert!(!s.contains("output line 00"));
    }

    #[test]
    fn installed_names_are_green() {
        let mut app = App::new(sample());
        app.handle_key(key('j')); // move selection off curl so its style is not reversed
        let t = render(&mut app, &mut Ui::default(), 140, 40);
        let (x, y) = find(&t, "curl").unwrap();
        assert_eq!(t.backend().buffer()[(x, y)].fg, Color::Green);
    }

    #[test]
    fn help_overlay() {
        let mut app = App::new(sample());
        app.handle_key(key('?'));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 45));
        for expected in [
            "NAVIGATION",
            "FILTERS",
            "ACTIONS",
            "Toggle upgradable",
            "Press any key to close",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
        assert!(!s.contains("WORLD FILE"));
        assert!(!s.contains("Export"), "{s}");
    }

    #[test]
    fn confirm_overlay() {
        let mut app = App::new(sample());
        app.handle_key(key('i'));
        let s = screen(&render(&mut app, &mut Ui::default(), 140, 40));
        assert!(
            s.contains("Are you sure you want to install the package: curl?"),
            "{s}"
        );
        assert!(s.contains("Confirm"));
        assert!(s.contains("Cancel"));
    }

    #[test]
    fn scrolls_to_keep_selection_visible_and_sets_page_size() {
        let pkgs: Vec<Package> = (0..200)
            .map(|i| pkg(&format!("pkg{i:03}"), false))
            .collect();
        let mut app = App::new(pkgs);
        let mut ui = Ui::default();
        render(&mut app, &mut ui, 140, 40);
        assert!(
            app.page_size > 5 && app.page_size < 40,
            "page size {}",
            app.page_size
        );
        for _ in 0..150 {
            app.handle_key(key('j'));
        }
        let s = screen(&render(&mut app, &mut ui, 140, 40));
        assert!(s.contains("pkg150"), "{s}");
        assert!(!s.contains("pkg000"));
    }

    #[test]
    fn small_terminal_does_not_panic() {
        let mut app = App::new(sample());
        app.handle_key(key('?'));
        render(&mut app, &mut Ui::default(), 20, 8);
        let mut app = App::new(sample());
        app.handle_key(key('i'));
        render(&mut app, &mut Ui::default(), 10, 4);
    }
}
