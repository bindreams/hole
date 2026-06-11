# stepstool

Elevation primitives for the "unprivileged parent, one elevated child" model:
the parent never gains or sheds privilege — sudo credential priming and
sudo-wrapped command construction on POSIX, elevation detection on Windows.

Born in [bindreams/hole](https://github.com/bindreams/hole) as the reusable
half of the abandoned `elevated:`-flag work (PR #456); salvaged for the
dev-console privilege model (#452/#455).
