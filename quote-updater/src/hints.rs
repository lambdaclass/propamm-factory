//! The operator hints whose wording depends on how the binary is run: how to reload it and
//! how to restart it. A binary that runs as a systemd user unit names it on the builder
//! ([`crate::UpdaterBuilder::systemd_unit`]) and is told `systemctl --user reload <unit>`;
//! one that names none is told the signal. Process-wide, set once: the unit is a fact
//! about the process, and threading it through every notice would touch six modules for
//! one string.

use std::sync::OnceLock;

static UNIT: OnceLock<&'static str> = OnceLock::new();

/// Names the unit. Once per process: the first run decides for any other, and a later,
/// different unit is refused with a warning rather than ignored in silence.
pub(crate) fn set_unit(unit: &'static str) {
    if let Err(first) = set_unit_in(&UNIT, unit) {
        tracing::warn!(
            "this process already runs as the `{first}` unit; `{unit}` is ignored in the \
             operator hints"
        );
    }
}

/// [`set_unit`] on a cell: `Ok` when `unit` is now the cell's (or already was), `Err`
/// with the unit that was named first when a different one was.
fn set_unit_in(cell: &OnceLock<&'static str>, unit: &'static str) -> Result<(), &'static str> {
    match cell.get() {
        Some(first) if *first == unit => Ok(()),
        Some(first) => Err(first),
        None => {
            let _ = cell.set(unit);
            Ok(())
        }
    }
}

/// The reload in a sentence: `` `systemctl --user reload <unit>` `` (as a command), or
/// `a SIGHUP`.
pub(crate) fn reload_in_prose() -> String {
    reload_in_prose_for(UNIT.get().copied())
}

/// What to do to reload, for a parenthesis: `systemctl --user reload <unit>`, or `SIGHUP`.
pub(crate) fn reload() -> String {
    reload_for(UNIT.get().copied())
}

/// The reload line's own form: `` `systemctl --user reload <unit>` (SIGHUP) ``, or `SIGHUP`.
pub(crate) fn reload_command() -> String {
    reload_command_for(UNIT.get().copied())
}

/// What follows "needs a restart rather than a reload": the command in parentheses, or
/// nothing.
pub(crate) fn restart_note() -> String {
    restart_note_for(UNIT.get().copied())
}

/// What the backoffice tells an operator who changed a setting: `` run `systemctl --user
/// restart <unit>` ``, or `restart the process`.
pub(crate) fn restart_instruction() -> String {
    restart_instruction_for(UNIT.get().copied())
}

fn reload_for(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!("systemctl --user reload {unit}"),
        None => "SIGHUP".to_owned(),
    }
}

fn reload_in_prose_for(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!("`systemctl --user reload {unit}`"),
        None => "a SIGHUP".to_owned(),
    }
}

fn reload_command_for(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!("`systemctl --user reload {unit}` (SIGHUP)"),
        None => "SIGHUP".to_owned(),
    }
}

fn restart_note_for(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!(" (`systemctl --user restart {unit}`)"),
        None => String::new(),
    }
}

fn restart_instruction_for(unit: Option<&str>) -> String {
    match unit {
        Some(unit) => format!("run `systemctl --user restart {unit}`"),
        None => "restart the process".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines with a unit, byte for byte; the signal without one. The
    /// process-wide setter is not exercised here: tests share the process.
    #[test]
    fn the_hints_name_the_unit_or_the_signal() {
        assert_eq!(
            reload_for(Some("example-quoter")),
            "systemctl --user reload example-quoter"
        );
        assert_eq!(reload_for(None), "SIGHUP");
        assert_eq!(
            reload_command_for(Some("example-quoter")),
            "`systemctl --user reload example-quoter` (SIGHUP)"
        );
        assert_eq!(reload_command_for(None), "SIGHUP");
        assert_eq!(
            restart_note_for(Some("example-quoter")),
            " (`systemctl --user restart example-quoter`)"
        );
        assert_eq!(restart_note_for(None), "");
        assert_eq!(
            restart_instruction_for(Some("example-quoter")),
            "run `systemctl --user restart example-quoter`"
        );
        assert_eq!(restart_instruction_for(None), "restart the process");
        assert_eq!(
            reload_in_prose_for(Some("example-quoter")),
            "`systemctl --user reload example-quoter`"
        );
        assert_eq!(reload_in_prose_for(None), "a SIGHUP");
    }

    /// The first unit named in a process is the one every hint prints; a second, different
    /// one is refused with the first, so the binary can say so, rather than ignored.
    #[test]
    fn a_second_unit_is_refused_with_the_first() {
        let cell = OnceLock::new();
        assert_eq!(set_unit_in(&cell, "a"), Ok(()));
        assert_eq!(
            set_unit_in(&cell, "a"),
            Ok(()),
            "the same unit again is nothing"
        );
        assert_eq!(set_unit_in(&cell, "b"), Err("a"));
        assert_eq!(cell.get(), Some(&"a"));
    }
}
