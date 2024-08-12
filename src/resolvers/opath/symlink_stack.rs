/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! SymlinkStack is used to emulate how `openat2::resolve_partial` treats
//! dangling symlinks.
//!
//! If we hit a non-existent path while resolving a symlink, we need to return
//! the `(current: Rc<File>, remaining_components: PathBuf)` we had when we hit
//! the symlink (effectively making the symlink resolution all-or-nothing). The
//! set of `(current, remaining_components)` set is stored within the
//! SymlinkStack and we add and or remove parts when we hit symlink and
//! non-symlink components respectively. This needs to be implemented as a stack
//! because of nested symlinks (if there is a dangling symlink 10 levels deep
//! into lookup, we need to return the *first* symlink we walked into to match
//! `openat2::resolve_partial`).
//!
//! Note that the stack is ONLY used for book-keeping to adjust what we *return*
//! in case of lookup errors. All of the path walking logic is still based on
//! remaining_components and expected_path!

use crate::utils::PathIterExt;

use std::{
    collections::VecDeque,
    error::Error as StdError,
    ffi::{OsStr, OsString},
    fmt,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    rc::Rc,
};

#[derive(Debug, PartialEq)]
pub enum SymlinkStackError {
    EmptyStack,
    BrokenStackEmpty { part: OsString },
    BrokenStackWrongComponent { part: OsString, expected: OsString },
}

impl fmt::Display for SymlinkStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStack => write!(f, "[internal] empty stack"),
            Self::BrokenStackEmpty { part } => {
                write!(f, "[internal error] broken symlink stack: trying to pop component {part:?} from an empty stack entry")
            }
            Self::BrokenStackWrongComponent { part, expected } => {
                write!(f, "[internal error] broken symlink stack: trying to pop component {part:?} but expected {expected:?}")
            }
        }
    }
}

impl StdError for SymlinkStackError {}

#[derive(Debug)]
struct SymlinkStackEntry<F: fmt::Debug> {
    /// The current directory and remaining path at the point where we entered
    /// this symlink.
    state: (Rc<F>, PathBuf),
    /// The remaining path components we have to walk from the symlink that lead
    /// us here. Once we finish walking these components, this symlink has been
    /// fully resolved and can be dropped from the stack (unless the trailing
    /// component was a symlink, see `swap_link` for details).
    unwalked_link_parts: VecDeque<OsString>,
}

#[derive(Debug)]
pub(crate) struct SymlinkStack<F: fmt::Debug>(VecDeque<SymlinkStackEntry<F>>);

impl<F: fmt::Debug> SymlinkStack<F> {
    fn do_push(&mut self, (dir, remaining): (&Rc<F>, PathBuf), link_target: PathBuf) {
        // Get a proper Rc<File>.
        let dir = Rc::clone(dir);

        // Split the link target and clean up any "" parts.
        let link_parts = link_target
            .raw_components()
            .map(OsString::from)
            // Drop any "" or "." no-op components.
            .filter(|part| !part.is_empty() && part.as_bytes() != b".")
            .collect::<VecDeque<OsString>>();

        self.0.push_back(SymlinkStackEntry {
            state: (dir, remaining),
            unwalked_link_parts: link_parts,
        })
    }

    fn do_pop(&mut self, part: &OsStr) -> Result<(), SymlinkStackError> {
        if part.as_bytes() == b"." {
            // "." components are no-ops -- we drop them in do_push().
            return Ok(());
        }
        let tail_entry = match self.0.len() {
            0 => return Err(SymlinkStackError::EmptyStack),
            n => self
                .0
                .get_mut(n - 1)
                .expect("VecDeque.get(len-1) should work"),
        };

        // Pop the next unwalked link component, but make sure the component
        // matches what we expect.
        match tail_entry.unwalked_link_parts.front() {
            None => return Err(SymlinkStackError::BrokenStackEmpty { part: part.into() }),
            Some(expected) => {
                if expected != part {
                    return Err(SymlinkStackError::BrokenStackWrongComponent {
                        part: part.into(),
                        expected: expected.into(),
                    });
                }
            }
        };

        // Drop the component.
        let _ = tail_entry.unwalked_link_parts.pop_front();

        // If that was the last unwalked link component, we *do not* remove the
        // entry here. That's done by pop_part() if we are dealing with a
        // non-symlink path component. swap_link() needs to keep this entry so
        // that if we we are in a "tail-chained" symlink and we hit a
        // non-existent path we return the right value from pop_top_symlink().
        Ok(())
    }

    pub(crate) fn pop_part(&mut self, part: &OsStr) -> Result<(), SymlinkStackError> {
        match self.do_pop(part) {
            Err(SymlinkStackError::EmptyStack) => return Ok(()),
            Err(err) => return Err(err),
            Ok(_) => (),
        };
        // Since this was a regular path component, clean up any "tail-chained"
        // symlinks in the stack (those without any remaining unwalked link
        // parts).
        // TODO: Use && let once <https://github.com/rust-lang/rust/issues/53667>
        //       is stabilised.
        while !self.0.is_empty() {
            let entry = self
                .0
                .back()
                .expect("should be able to get last element in non-empty stack");
            if entry.unwalked_link_parts.is_empty() {
                self.0.pop_back();
            } else {
                // Quit once we hit a non-empty entry.
                break;
            }
        }
        Ok(())
    }

    pub(crate) fn swap_link(
        &mut self,
        link_part: &OsStr,
        (dir, remaining): (&Rc<F>, PathBuf),
        link_target: PathBuf,
    ) -> Result<(), SymlinkStackError> {
        // If we are currently inside a symlink resolution, remove the symlink
        // component from the last symlink entry, but don't remove the entry
        // itself even if it's empty. If we are a "tail-chained" symlink (a
        // trailing symlink we hit during a symlink resolution) we need to keep
        // the original symlink until we finish the resolution to return the
        // right result if this link chain turns out to be dangling.
        match self.do_pop(link_part) {
            Err(SymlinkStackError::EmptyStack) | Ok(_) => {
                // Push the component regardless of whether the stack was empty.
                self.do_push((dir, remaining), link_target);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn pop_top_symlink(&mut self) -> Option<(Rc<F>, PathBuf)> {
        self.0.pop_front().map(|entry| entry.state)
    }

    pub(crate) fn new() -> Self {
        Self(VecDeque::new())
    }
}

#[cfg(test)]
mod tests {
    use super::SymlinkStackError;

    use std::{
        path::{Path, PathBuf},
        rc::Rc,
    };

    use pretty_assertions::assert_eq;

    // Use strings rather than actual files for the symlink stack tests.
    type SymlinkStack = super::SymlinkStack<String>;

    fn dump_stack(stack: &SymlinkStack) {
        for (idx, entry) in stack.0.iter().enumerate() {
            println!(
                "ss[{idx}]: <{}>/{:?} [->{:?}]",
                entry.state.0, entry.state.1, entry.unwalked_link_parts
            );
        }
    }

    macro_rules! stack_ops {
        ($ss:ident @impl $do:block => $expected_result:expr) => {
            println!("> before operation");
            dump_stack(&$ss);

            let res = $do;

            println!("> after operation");
            dump_stack(&$ss);

            assert_eq!(res, $expected_result, "unexpected result");
        };

        ($ss:ident @fn swap_link($link_part:expr, $dir:expr, $remaining:expr, $link_target:expr) => $expected_result:expr) => {
            stack_ops! {
                $ss @impl {
                    let link_part = Path::new($link_part).as_os_str();
                    let dir = Rc::new($dir.into());
                    let remaining = PathBuf::from($remaining);
                    let link_target = PathBuf::from($link_target);

                    $ss.swap_link(link_part, (&dir, remaining), link_target)
                } => $expected_result
            }
        };

        ($ss:ident @fn pop_part($part:expr) => $expected_result:expr) => {
            stack_ops! {
                $ss @impl {
                    let part = Path::new($part).as_os_str();

                    $ss.pop_part(part)
                } => $expected_result
            }
        };

        ($ss:ident @fn pop_top_symlink() => $expected_result:expr) => {
            let expected_result: Option<(String, PathBuf)> = $expected_result
                .map(|(current, remaining)| (current.into(), remaining.into()));

            stack_ops! {
                $ss @impl {
                    $ss.pop_top_symlink()
                        .map(|(dir, current)| (String::from(&*dir), current))
                } => expected_result
            }
        };

        ([$ss:ident] { $( $op:ident ( $($args:tt)* ) => $expected_result:expr );* $(;)? }) => {
            $(
                {
                    println!("-- operation {}{:?}", stringify!($op), ($($args)*));
                    stack_ops! {
                        $ss @fn $op ( $($args)* ) => $expected_result
                    }
                }
            )*
        }
    }

    macro_rules! stack_content {
        ([$ss:ident] == {
            $((($current:expr, $remaining:expr), {$($unwalked_parts:expr),* $(,)?})),* $(,)?
        }) => {
            {
                let stack_contents = $ss.
                    0
                    .iter()
                    .map(|entry| {(
                        (String::from(&*entry.state.0), entry.state.1.clone()),
                        entry.unwalked_link_parts.iter().cloned().collect::<Vec<_>>(),
                    )})
                    .collect::<Vec<_>>();
                let expected = vec![
                    $(
                        ((String::from($current), $remaining.into()), vec![$($unwalked_parts.into()),*])
                    ),*
                ];

                assert_eq!(stack_contents, expected, "stack content mismatch")
            }
        }
    }

    #[test]
    fn basic() {
        let mut stack = SymlinkStack::new();

        stack_ops! {
            [stack] {
                swap_link("foo", "A", "anotherbit", "bar/baz") => Ok(());
                swap_link("bar", "B", "baz", "abcd") => Ok(());
                pop_part("abcd") => Ok(());
                swap_link("baz", "C", "", "taillink") => Ok(());
                pop_part("taillink") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");
        assert_eq!(
            stack.pop_top_symlink(),
            None,
            "pop_top_symlink should give None with empty stack"
        );

        stack_ops! {
            [stack] {
                pop_part("anotherbit") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");
        assert_eq!(
            stack.pop_top_symlink(),
            None,
            "pop_top_symlink should give None with empty stack"
        );
    }

    #[test]
    fn basic_pop_top_symlink() {
        let mut stack = SymlinkStack::new();

        stack_ops! {
            [stack] {
                swap_link("foo", "A", "anotherbit", "bar/baz") => Ok(());
                swap_link("bar", "B", "baz", "abcd") => Ok(());
                pop_part("abcd") => Ok(());
                swap_link("baz", "C", "", "taillink") => Ok(());
                pop_top_symlink() => Some(("A", "anotherbit"));
            }
        };
    }

    #[test]
    fn bad_pop_part() {
        let mut stack = SymlinkStack::new();

        stack_ops! {
            [stack] {
                swap_link("foo", "A", "anotherbit", "bar/baz") => Ok(());
                swap_link("bar", "B", "baz", "abcd") => Ok(());
                swap_link("bad", "C", "", "taillink") => Err(SymlinkStackError::BrokenStackWrongComponent {
                    part: "bad".into(),
                    expected: "abcd".into(),
                });
                pop_part("abcd") => Ok(());
                swap_link("baz", "C", "", "taillink") => Ok(());
                pop_part("bad") => Err(SymlinkStackError::BrokenStackWrongComponent {
                    part: "bad".into(),
                    expected: "taillink".into(),
                });
                pop_part("taillink") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");

        stack_ops! {
            [stack] {
                pop_part("anotherbit") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");
    }

    #[test]
    fn basic_tail_chain() {
        let mut stack = SymlinkStack::new();

        stack_ops! {
            [stack] {
                swap_link("foo", "A", "", "tailA") => Ok(());
                swap_link("tailA", "B", "", "tailB") => Ok(());
                swap_link("tailB", "C", "", "tailC") => Ok(());
                swap_link("tailC", "D", "", "tailD") => Ok(());
                swap_link("tailD", "E", "", "foo/taillink") => Ok(());
            }
        };
        stack_content! {
            [stack] == {
                // The top 4 entries should have no unwalked links.
                (("A", ""), {}),
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry should be foo/taillink.
                (("E", ""), {"foo", "taillink"}),
            }
        };

        // Popping "foo" should keep the tail-chain.
        stack_ops! {
            [stack] {
                pop_part("foo") => Ok(());
            }
        };
        stack_content! {
            [stack] == {
                // The top 4 entries should have no unwalked links.
                (("A", ""), {}),
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry should be just taillink.
                (("E", ""), {"taillink"}),
            }
        };

        // Popping "taillink" should empty the stack.
        stack_ops! {
            [stack] {
                pop_part("taillink") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");
    }

    #[test]
    fn stacked_tail_chain() {
        let mut stack = SymlinkStack::new();

        stack_ops! {
            [stack] {
                swap_link("foo", "A", "", "tailA/subdir") => Ok(());
                // First tail-chain.
                swap_link("tailA", "B", "", "tailB") => Ok(());
                swap_link("tailB", "C", "", "tailC") => Ok(());
                swap_link("tailC", "D", "", "tailD") => Ok(());
                swap_link("tailD", "E", "", "taillink1/subdir") => Ok(());
                // Second tail-chain.
                swap_link("taillink1", "F", "", "tailE") => Ok(());
                swap_link("tailE", "G", "", "tailF") => Ok(());
                swap_link("tailF", "H", "", "tailG") => Ok(());
                swap_link("tailG", "I", "", "tailH") => Ok(());
                swap_link("tailH", "J", "", "tailI") => Ok(());
                swap_link("tailI", "K", "", "taillink2/..") => Ok(());
            }
        };
        stack_content! {
            [stack] == {
                // The top entry is not a tail-chain.
                (("A", ""), {"subdir"}),
                // The first tail-chain should have no unwalked links.
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry in the first tail-chain.
                (("E", ""), {"subdir"}),
                // The second tail-chain should have no unwalked links.
                (("F", ""), {}),
                (("G", ""), {}),
                (("H", ""), {}),
                (("I", ""), {}),
                (("J", ""), {}),
                // Final entry in the second tail-chain.
                (("K", ""), {"taillink2", ".."}),
            }
        };

        // Check that nonsense operations don't break the stack.
        stack_ops! {
            [stack] {
                // Trying to pop "." should do nothing.
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                pop_part(".") => Ok(());
                // Popping any of the early tail chain entries must fail.
                pop_part("subdir") => Err(SymlinkStackError::BrokenStackWrongComponent {
                    part: "subdir".into(),
                    expected: "taillink2".into(),
                });
                pop_part("..") => Err(SymlinkStackError::BrokenStackWrongComponent {
                    part: "..".into(),
                    expected: "taillink2".into(),
                });
            }
        };

        // NOTE: Same contents as above.
        stack_content! {
            [stack] == {
                // The top entry is not a tail-chain.
                (("A", ""), {"subdir"}),
                // The first tail-chain should have no unwalked links.
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry in the first tail-chain.
                (("E", ""), {"subdir"}),
                // The second tail-chain should have no unwalked links.
                (("F", ""), {}),
                (("G", ""), {}),
                (("H", ""), {}),
                (("I", ""), {}),
                (("J", ""), {}),
                // Final entry in the second tail-chain.
                (("K", ""), {"taillink2", ".."}),
            }
        };

        // Popping part of the last chain should keep both tail-chains.
        stack_ops! {
            [stack] {
                pop_part("taillink2") => Ok(());
            }
        }
        stack_content! {
            [stack] == {
                // The top entry is not a tail-chain.
                (("A", ""), {"subdir"}),
                // The first tail-chain should have no unwalked links.
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry in the first tail-chain.
                (("E", ""), {"subdir"}),
                // The second tail-chain should have no unwalked links.
                (("F", ""), {}),
                (("G", ""), {}),
                (("H", ""), {}),
                (("I", ""), {}),
                (("J", ""), {}),
                // Final entry in the second tail-chain.
                (("K", ""), {".."}),
            }
        };

        // Popping the last entry should only drop the final tail-chain.
        stack_ops! {
            [stack] {
                pop_part("..") => Ok(());
            }
        }
        stack_content! {
            [stack] == {
                // The top entry is not a tail-chain.
                (("A", ""), {"subdir"}),
                // The first tail-chain should have no unwalked links.
                (("B", ""), {}),
                (("C", ""), {}),
                (("D", ""), {}),
                // Final entry in the first tail-chain.
                (("E", ""), {"subdir"}),
            }
        };

        // Popping the last entry should only drop the tail-chain.
        stack_ops! {
            [stack] {
                pop_part("subdir") => Ok(());
            }
        }
        stack_content! {
            [stack] == {
                // The top entry is not a tail-chain.
                (("A", ""), {"subdir"}),
            }
        };

        // Popping "subdir" should empty the stack.
        stack_ops! {
            [stack] {
                pop_part("subdir") => Ok(());
            }
        };
        assert!(stack.0.is_empty(), "stack should be empty");
    }
}
