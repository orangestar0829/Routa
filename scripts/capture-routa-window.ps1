param(
  [Parameter(Mandatory)][int]$ProcessId,
  [string]$Output,
  [int]$Width
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RoutaCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    public struct Point { public int X, Y; public Point(int x, int y) { X=x; Y=y; } }
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hwnd, int command);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, uint attr, out Rect rect, int bytes);
}
'@

[void][RoutaCapture]::SetProcessDpiAwarenessContext([IntPtr]::new(-4))
$proc = Get-Process -Id $ProcessId -ErrorAction Stop
$hwnd = $proc.MainWindowHandle
if ($proc.ProcessName -ne 'routa' -or $hwnd -eq [IntPtr]::Zero) {
  throw 'No native Routa application window is available'
}
[void][RoutaCapture]::ShowWindowAsync($hwnd, 9) # SW_RESTORE
$rect = New-Object 'RoutaCapture+Rect'
if (![RoutaCapture]::GetWindowRect($hwnd, [ref]$rect)) { throw 'Could not read Routa window bounds' }
if ($Width) {
  $dpi = [Math]::Max(96, [int][RoutaCapture]::GetDpiForWindow($hwnd))
  $physicalWidth = [int][Math]::Round($Width * $dpi / 96)
  if (![RoutaCapture]::SetWindowPos($hwnd, [IntPtr]::Zero, 0, 0, $physicalWidth, ($rect.Bottom - $rect.Top), 0x0014)) {
    throw "Could not resize the Routa application window to ${Width}px"
  }
  return
}
if (!$Output) { throw 'Specify -Output for a native screenshot or -Width for a resize' }

function Test-RenderedContent([System.Drawing.Bitmap]$Image) {
  # Ignore the title bar and border: a blank WebView can still have OS chrome.
  $colors = [System.Collections.Generic.HashSet[int]]::new()
  $min = 255
  $max = 0
  for ($y = 58; $y -lt ($Image.Height - 26); $y += 13) {
    for ($x = 18; $x -lt ($Image.Width - 18); $x += 13) {
      $pixel = $Image.GetPixel($x, $y)
      [void]$colors.Add($pixel.ToArgb())
      $value = [int](($pixel.R + $pixel.G + $pixel.B) / 3)
      $min = [Math]::Min($min, $value)
      $max = [Math]::Max($max, $value)
    }
  }
  return ($colors.Count -gt 12 -and ($max - $min) -gt 55)
}

function Save-NativeImage($Bounds, [bool]$Desktop) {
  $width = $Bounds.Right - $Bounds.Left
  $height = $Bounds.Bottom - $Bounds.Top
  if ($width -lt 400 -or $height -lt 350) { return $false }
  $bitmap = [System.Drawing.Bitmap]::new($width, $height)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  try {
    if ($Desktop) {
      $graphics.CopyFromScreen($Bounds.Left, $Bounds.Top, 0, 0, $bitmap.Size)
    } else {
      $dc = $graphics.GetHdc()
      try { $captured = [RoutaCapture]::PrintWindow($hwnd, $dc, 2) }
      finally { $graphics.ReleaseHdc($dc) }
      if (!$captured) { return $false }
    }
    if (!(Test-RenderedContent $bitmap)) { return $false }
    $bitmap.Save($Output, [System.Drawing.Imaging.ImageFormat]::Png)
    return $true
  } finally {
    $graphics.Dispose()
    $bitmap.Dispose()
  }
}

try {
  # Bring forward only the fixture window and copy only its visible frame.
  [void][RoutaCapture]::SetWindowPos($hwnd, [IntPtr]::new(-1), 0, 0, 0, 0, 0x0013)
  [void][RoutaCapture]::SetForegroundWindow($hwnd)
  Start-Sleep -Milliseconds 350
  [void][RoutaCapture]::GetWindowRect($hwnd, [ref]$rect)
  $frame = New-Object 'RoutaCapture+Rect'
  if ([RoutaCapture]::DwmGetWindowAttribute($hwnd, 9, [ref]$frame, 16) -ne 0) { $frame = $rect }
  $screenX = [RoutaCapture]::GetSystemMetrics(76)
  $screenY = [RoutaCapture]::GetSystemMetrics(77)
  $screenRight = $screenX + [RoutaCapture]::GetSystemMetrics(78)
  $screenBottom = $screenY + [RoutaCapture]::GetSystemMetrics(79)
  if ($frame.Left -ge $screenX -and $frame.Top -ge $screenY -and
      $frame.Right -le $screenRight -and $frame.Bottom -le $screenBottom) {
    $owned = $true
    foreach ($x in @($frame.Left + 18; [int](($frame.Left + $frame.Right) / 2); $frame.Right - 18)) {
      foreach ($y in @($frame.Top + 58; [int](($frame.Top + $frame.Bottom) / 2); $frame.Bottom - 26)) {
        $point = [RoutaCapture+Point]::new($x, $y)
        $target = [RoutaCapture]::WindowFromPoint($point)
        if ([RoutaCapture]::GetAncestor($target, 2) -ne $hwnd) { $owned = $false }
      }
    }
    if ($owned -and (Save-NativeImage $frame $true)) { Write-Output 'windows-desktop'; return }
  }
} catch {
  Write-Warning "Desktop capture failed; trying PrintWindow: $($_.Exception.Message)"
} finally {
  [void][RoutaCapture]::SetWindowPos($hwnd, [IntPtr]::new(-2), 0, 0, 0, 0, 0x0013)
}
if (Save-NativeImage $rect $false) { Write-Output 'windows-printwindow'; return }
throw 'No usable native window pixels were returned'
