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
//!   their own relocated profile is followed; their link to `/etc` is not.
//!
//! The final name of a file operation is not a step of the walk and is never followed.

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

/// A folder the walk stands in, for the checks on where it may create and end.
pub(super) enum Folder<Id> {
    /// One that was there already, with its owner.
    Existing(Owner<Id>),
    /// One this walk just made. The file system gives it to the process that made it, but it was
    /// made inside a folder [`Trail::create_in`] admitted, so it is as trusted as that one.
    Made,
}

/// What a walk has followed so far.
pub(super) struct Trail<Id> {
    /// The unprivileged owner of a link the walk followed, if any.
    led_by: Option<Id>,
}

impl<Id: Clone + PartialEq> Trail<Id> {
    pub(super) fn new() -> Self {
        Trail { led_by: None }
    }

    /// Admits following `link`, which sits in the folder `dir`, or refuses it.
    pub(super) fn follow(&mut self, dir: &Owner<Id>, link: &Owner<Id>) -> Result<(), Refusal> {
        if !dir.may_enter(link) {
            return Err(Refusal::Symlink);
        }
        let Owner::User(owner) = link else { return Ok(()) };
        match &self.led_by {
            None => self.led_by = Some(owner.clone()),
            Some(led_by) if led_by == owner => {}
            Some(_) => return Err(Refusal::Symlink),
        }
        Ok(())
    }

    /// Admits creating a folder in `dir`.
    pub(super) fn create_in(&self, dir: &Folder<Id>) -> Result<(), Refusal> {
        self.stays_with_the_link_owner(dir)
    }

    /// Admits the walk's last folder being `dir`.
    pub(super) fn end_at(&self, dir: &Folder<Id>) -> Result<(), Refusal> {
        self.stays_with_the_link_owner(dir)
    }

    fn stays_with_the_link_owner(&self, dir: &Folder<Id>) -> Result<(), Refusal> {
        match (&self.led_by, dir) {
            (None, _) | (Some(_), Folder::Made) => Ok(()),
            (Some(led_by), Folder::Existing(Owner::User(owner))) if led_by == owner => Ok(()),
            (Some(_), Folder::Existing(_)) => Err(Refusal::Symlink),
        }
    }
}

#[cfg(test)]
#[path = "trail_tests.rs"]
mod trail_tests;
