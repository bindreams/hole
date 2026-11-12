# Defines `Get-ProcessImagePath`, dot-sourced by every script that must say where a hole.exe runs from.
#
# `Get-Process`'s Path is empty for a process whose module list cannot be read yet (still in loader
# initialisation), as is Win32_Process.ExecutablePath; QueryFullProcessImageName reads the image name
# the kernel holds, which exists from process creation.
Add-Type -Namespace HoleKill -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, System.Text.StringBuilder path, ref uint size);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@

# The image path of a process, or $null when even the kernel's answer cannot be had.
function Get-ProcessImagePath([System.Diagnostics.Process]$Process) {
    if ($Process.Path) { return $Process.Path }
    $PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    $handle = [HoleKill.Native]::OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION, $false, $Process.Id)
    if ($handle -eq [IntPtr]::Zero) { return $null }
    try {
        $path = [Text.StringBuilder]::new(32768)
        [uint32]$size = $path.Capacity
        if ([HoleKill.Native]::QueryFullProcessImageNameW($handle, 0, $path, [ref]$size)) { return $path.ToString() }
        return $null
    } finally { [void][HoleKill.Native]::CloseHandle($handle) }
}
