# kill-group

Spawn a child process as the root of a **kill-group** — a Windows Job Object
with `KILL_ON_JOB_CLOSE` or a Unix process group — so that the child's whole
descendant tree can be gracefully signalled (`SIGTERM` to the group /
`CTRL_BREAK`), hard-killed, and is reaped as a unit when the guard drops,
even if intermediate parents already exited.

Born in [bindreams/hole](https://github.com/bindreams/hole) as garter's
internal `proc_group` module (#197); extracted for reuse.
