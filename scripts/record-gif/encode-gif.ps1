# Encode a directory of PNG frames into an animated GIF (Windows-only: uses WPF's
# GifBitmapEncoder), then patch in looping + frame delays via patch-gif.mjs
# (GifBitmapEncoder emits neither a NETSCAPE loop extension nor GCE delay blocks).
# Usage: .\encode-gif.ps1 -FrameDir <dir of *.png> -OutFile <out.gif> [-DelayCs 160]
param(
    [Parameter(Mandatory=$true)][string]$FrameDir,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [int]$DelayCs = 160
)
Add-Type -AssemblyName PresentationCore

$enc = New-Object System.Windows.Media.Imaging.GifBitmapEncoder
Get-ChildItem $FrameDir -Filter *.png | Sort-Object Name | ForEach-Object {
    $src = New-Object System.Windows.Media.Imaging.BitmapImage
    $src.BeginInit()
    $src.UriSource = $_.FullName
    $src.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $src.EndInit()
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($src))
}
$raw = Join-Path $env:TEMP "mcpglass-gif-raw.gif"
$fs = [System.IO.File]::Create($raw)
$enc.Save($fs)
$fs.Close()

node (Join-Path $PSScriptRoot "patch-gif.mjs") $raw $OutFile $DelayCs
Remove-Item $raw -Confirm:$false
