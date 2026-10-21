//! Which links a [`super::Dir`] walk follows, and where it may end.
//!
//! A privileged process walks a path whose folders a user may own, so a link in it can be the
//! user's. The rule is systemd's `chase()` with `CHASE_SAFE`: a walk never moves from a folder an
//! unprivileged user owns into one somebody else owns. systemd's own check lets any step away from
//! a privileged folder pass, and a user's link planted in a privileged one (`/tmp`) then leads
//! anywhere: the check never sees the link's owner, and an absolute target restarts at a
//! privileged `/`. This module closes both:
//!
//! - A link is judged by its own owner as well as by the folder it sits in
//!   ([`Trail::follow`]): a system-owned link inside a user's folder is a hard link the user
//!   planted and is refused.
//! - A link an unprivileged user owns binds the walk to that user. The walk may pass through
//!   anyone's folders (an absolute target starts at `/`), but it may create only in that user's
//!   folders ([`Trail::create_in`]) and must end in one ([`Trail::end_at`]). A user's link into
//!   their own relocated profile is followed; their link to `/etc` is not. A folder a bound walk
//!   makes is given to that user at once, so that the next walk through the link finds it theirs.
//! - The walk follows at most the number of links the OS itself follows in one path ([`Trail::new`]).
//!
//! The final name of a file operation is not a step of the walk and is never followed.

use std::io;

use super::Refusal;

/// Who owns a folder or a link, as far as the rule cares: the system, or one unprivileged principal.
///
/// Unix: root, or a uid. Windows: SYSTEM, Administrators and TrustedInstaller, or a SID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Owner<Id> {
    Privileged,
    User(Id),
}

impl<Id: PartialEq> Owner<Id> {
    /// Whether a walk may move from something `self` owns into something `to` owns: out of a
    /// privileged one into anything, out of a user's only into the same user's.
    pub(super) fn may_enter(&self, to: &Self) -> bool {
        match self {
            Owner::Privileged => true,
            Owner::User(from) => matches!(to, Owner::User(to) if to == from),
        }
    }
}

/// Whether a file `file` owns, with `links` names, in a folder `dir` reads the owner of, may be read by a privileged
/// reader: one the folder's own user owns (their own file, whatever links it has), or one the system owns that has no
/// second name. This refuses a second name a user adds, by a hard link, to a file they do not own: the file keeps its
/// owner and gains a link. It does not refuse a file the system owns that the user moved into the folder, which keeps
/// its owner and its one link; what a reader of such a file may log is the reader's own rule, not this one. The
/// folder's owner is read only when the file is a user's.
pub(super) fn may_read<Id: PartialEq>(
    file: &Owner<Id>,
    links: u64,
    dir: impl FnOnce() -> io::Result<Owner<Id>>,
) -> io::Result<bool> {
    match file {
        Owner::Privileged => Ok(links == 1),
        Owner::User(owner) => Ok(matches!(dir()?, Owner::User(dir_owner) if &dir_owner == owner)),
    }
}

/// What a walk has followed so far.
pub(super) struct Trail<Id> {
    /// The unprivileged owner of a link the walk followed, if any.
    led_by: Option<Id>,
    /// Links followed so far.
    followed: usize,
    /// How many links a walk may follow: the OS's own bound on a path.
    limit: usize,
}

impl<Id: Clone + PartialEq> Trail<Id> {
    /// A walk that may follow `limit` links. A user plants them and each may name the next several times, so
    /// without a bound a short chain costs exponential time; the bound is the one the OS itself applies to a path.
    pub(super) fn new(limit: usize) -> Self {
        Trail {
            led_by: None,
            followed: 0,
            limit,
        }
    }

    /// The unprivileged owner the walk is bound to, once it followed one's link.
    pub(super) fn led_by(&self) -> Option<&Id> {
        self.led_by.as_ref()
    }

    /// Admits following `link`, which sits in the folder `dir`, or refuses it.
    pub(super) fn follow(&mut self, dir: &Owner<Id>, link: &Owner<Id>) -> Result<(), Refusal> {
        if self.followed >= self.limit || !dir.may_enter(link) {
            return Err(Refusal::Symlink);
        }
        if let Owner::User(owner) = link {
            match &self.led_by {
                None => self.led_by = Some(owner.clone()),
                Some(led_by) if led_by == owner => {}
                Some(_) => return Err(Refusal::Symlink),
            }
        }
        self.followed += 1;
        Ok(())
    }

    /// Admits creating a folder in the folder whose owner `dir` reads.
    pub(super) fn create_in(&self, dir: impl FnOnce() -> io::Result<Owner<Id>>) -> io::Result<()> {
        self.stays_with_the_link_owner(dir)
    }

    /// Admits the walk's last folder being the one whose owner `dir` reads.
    pub(super) fn end_at(&self, dir: impl FnOnce() -> io::Result<Owner<Id>>) -> io::Result<()> {
        self.stays_with_the_link_owner(dir)
    }

    /// A walk bound to no one has nothing to stay with and does not read the owner at all: a folder whose
    /// permissions the caller cannot read is still on a path no link led to.
    fn stays_with_the_link_owner(&self, dir: impl FnOnce() -> io::Result<Owner<Id>>) -> io::Result<()> {
        let Some(led_by) = &self.led_by else { return Ok(()) };
        match dir()? {
            Owner::User(owner) if &owner == led_by => Ok(()),
            _ => Err(Refusal::Symlink.into_io_error()),
        }
    }
}

#[cfg(test)]
#[path = "trail_tests.rs"]
mod trail_tests;
