# Commit messages

Pull request titles and commit subjects follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>)?: <description>
```

The scope is optional, and a trailing `!` after the type or scope marks a breaking change. The type is one of the values
under `types:` in {src}`.github/workflows/semantic-pr.yaml`; that file is the list, and this page does not copy it.

## Why the format matters

`main` allows squash and rebase merges. A squash merge lands as one commit whose subject comes from the pull request's
title (or from the commit's own subject, for a one-commit pull request). A rebase merge keeps each commit's own subject.
So both the title and the commit subjects of a change are read later.

- The `Validate PR title` check ({src}`.github/workflows/semantic-pr.yaml`) rejects a pull request whose title does not
  match. It is one of the required checks. Rename with `gh pr edit <N> --title "..."`.
- The release notes are built from the commit subjects. {src}`scripts/generate-release-notes.py` groups the commits since
  the track's previous tag by type, using the categories in {src}`.github/release-categories.yaml`. A commit with no type, or with a
  type no category lists, goes under "Other".
- Each of the four release tracks (`hole`, `garter`, `galoshes`, `ex-ray`) lists only commits that touched the paths in
  its own `.github/release-<track>.yaml`.

To add a type, add it to `semantic-pr.yaml`, and optionally to a category in `release-categories.yaml`; without a
category it falls under "Other".
