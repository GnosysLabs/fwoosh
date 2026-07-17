[CmdletBinding()]
param(
  [string]$PackageIdentityName = $env:FWOOSH_MSIX_IDENTITY_NAME,
  [string]$Publisher = $env:FWOOSH_MSIX_PUBLISHER,
  [string]$PublisherDisplayName = $env:FWOOSH_MSIX_PUBLISHER_DISPLAY_NAME,
  [switch]$Development
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$packageJson = Get-Content -Raw (Join-Path $repoRoot "package.json") | ConvertFrom-Json
$versionParts = @($packageJson.version.Split("."))
$invalidVersionParts = @($versionParts | Where-Object { $_ -notmatch '^\d+$' })
if ($versionParts.Count -ne 3 -or $invalidVersionParts.Count -gt 0) {
  throw "MSIX packaging requires an x.y.z application version."
}
$msixVersion = "$($versionParts[0]).$($versionParts[1]).$($versionParts[2]).0"

if ($Development) {
  $PackageIdentityName = "Fwoosh.Development"
  $Publisher = "CN=Fwoosh Development, OID.2.25.311729368913984317654407730594956997722=1"
  $PublisherDisplayName = "Fwoosh Development"
}
if (-not $PackageIdentityName -or -not $Publisher -or -not $PublisherDisplayName) {
  throw "Set FWOOSH_MSIX_IDENTITY_NAME, FWOOSH_MSIX_PUBLISHER, and FWOOSH_MSIX_PUBLISHER_DISPLAY_NAME from Partner Center, or pass -Development."
}

$legalDocuments = @(
  (Join-Path $repoRoot "docs\terms-of-use.md"),
  (Join-Path $repoRoot "docs\privacy-policy.md")
)
if (-not $Development) {
  $legalPlaceholderPattern = '\[(LEGAL ENTITY / FWOOSH MAINTAINERS|MAILING ADDRESS OR BUSINESS ADDRESS|PRIVACY CONTACT EMAIL|GENERAL CONTACT EMAIL|PROVINCE / STATE AND COUNTRY|CITY, PROVINCE / STATE AND COUNTRY)\]'
  $incompleteDocuments = @($legalDocuments | Where-Object {
    (Get-Content -Raw -LiteralPath $_) -match $legalPlaceholderPattern
  })
  if ($incompleteDocuments.Count -gt 0) {
    throw "Complete the legal-document placeholders before creating a Store package: $($incompleteDocuments -join ', ')"
  }
}

Push-Location $repoRoot
try {
  & npm run version:check
  if ($LASTEXITCODE -ne 0) { throw "Version validation failed." }

  & npm run tauri -- build --target x86_64-pc-windows-msvc --no-bundle --ci
  if ($LASTEXITCODE -ne 0) { throw "Tauri release build failed." }

  $artifactRoot = Join-Path $repoRoot "artifacts\msix"
  $stagingRoot = Join-Path $artifactRoot "staging"
  $uploadRoot = Join-Path $artifactRoot "upload"
  foreach ($path in @($stagingRoot, $uploadRoot)) {
    $fullPath = [System.IO.Path]::GetFullPath($path)
    if (-not $fullPath.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to clean a path outside the repository: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
      Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
  }

  $assetsRoot = Join-Path $stagingRoot "Assets"
  $legalRoot = Join-Path $stagingRoot "Legal"
  New-Item -ItemType Directory -Path $assetsRoot, $legalRoot -Force | Out-Null

  $releaseRoot = Join-Path $repoRoot "src-tauri\target\x86_64-pc-windows-msvc\release"
  Copy-Item -LiteralPath (Join-Path $releaseRoot "fwoosh.exe") -Destination (Join-Path $stagingRoot "Fwoosh.exe")
  Copy-Item -LiteralPath $legalDocuments -Destination $legalRoot

  $iconRoot = Join-Path $repoRoot "src-tauri\icons"
  foreach ($icon in @("StoreLogo.png", "Square44x44Logo.png", "Square150x150Logo.png", "Square310x310Logo.png")) {
    Copy-Item -LiteralPath (Join-Path $iconRoot $icon) -Destination $assetsRoot
  }

  [xml]$manifest = Get-Content -Raw (Join-Path $repoRoot "src-tauri\msix\AppxManifest.template.xml")
  $namespace = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
  $namespace.AddNamespace("f", $manifest.DocumentElement.NamespaceURI)
  $identity = $manifest.SelectSingleNode("/f:Package/f:Identity", $namespace)
  $identity.SetAttribute("Name", $PackageIdentityName)
  $identity.SetAttribute("Publisher", $Publisher)
  $identity.SetAttribute("Version", $msixVersion)
  $publisherNode = $manifest.SelectSingleNode("/f:Package/f:Properties/f:PublisherDisplayName", $namespace)
  $publisherNode.InnerText = $PublisherDisplayName

  $manifestPath = Join-Path $stagingRoot "AppxManifest.xml"
  $xmlSettings = New-Object System.Xml.XmlWriterSettings
  $xmlSettings.Indent = $true
  $xmlSettings.Encoding = New-Object System.Text.UTF8Encoding($false)
  $writer = [System.Xml.XmlWriter]::Create($manifestPath, $xmlSettings)
  try { $manifest.Save($writer) } finally { $writer.Dispose() }

  $makeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter makeappx.exe |
    Where-Object { $_.FullName -match '\\x64\\makeappx\.exe$' } |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1 -ExpandProperty FullName
  if (-not $makeAppx) { throw "makeappx.exe was not found. Install the Windows SDK." }

  $msixPath = Join-Path $artifactRoot "Fwoosh_$($packageJson.version)_x64.msix"
  if (Test-Path -LiteralPath $msixPath) { Remove-Item -LiteralPath $msixPath -Force }
  & $makeAppx pack /d $stagingRoot /p $msixPath /o
  if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed." }

  Copy-Item -LiteralPath $msixPath -Destination $uploadRoot
  $pdbPath = Join-Path $releaseRoot "fwoosh.pdb"
  if (Test-Path -LiteralPath $pdbPath) {
    $symbolZip = Join-Path $artifactRoot "Fwoosh.appxsym.zip"
    $symbolPath = Join-Path $uploadRoot "Fwoosh.appxsym"
    Compress-Archive -LiteralPath $pdbPath -DestinationPath $symbolZip -Force
    Move-Item -LiteralPath $symbolZip -Destination $symbolPath -Force
  }
  $uploadZip = Join-Path $artifactRoot "Fwoosh_$($packageJson.version)_x64.zip"
  $uploadPath = Join-Path $artifactRoot "Fwoosh_$($packageJson.version)_x64.msixupload"
  Compress-Archive -Path (Join-Path $uploadRoot "*") -DestinationPath $uploadZip -Force
  Move-Item -LiteralPath $uploadZip -Destination $uploadPath -Force

  Get-FileHash -Algorithm SHA256 $msixPath, $uploadPath |
    ForEach-Object { "$($_.Hash.ToLowerInvariant()) *$([System.IO.Path]::GetFileName($_.Path))" } |
    Set-Content -Path (Join-Path $artifactRoot "fwoosh-msix.sha256") -Encoding ascii

  Write-Host "Created $msixPath"
  Write-Host "Created $uploadPath"
} finally {
  Pop-Location
}
