# PowerShell script to create a release package
$version = "1.0.0"
$releaseDir = "NIDS-v$version"
$zipFile = "NIDS-v$version.zip"

# Create release directory
New-Item -ItemType Directory -Path $releaseDir -Force

# Copy all necessary files
$filesToInclude = @(
    "app.py",
    "*.py",
    "templates/**",
    "static/**",
    "requirements.txt",
    "install_windows.bat",
    "start_nids.bat",
    "QUICK_START_GUIDE.md",
    "README.md"
)

foreach ($file in $filesToInclude) {
    Copy-Item -Path $file -Destination $releaseDir -Recurse -Force
}

# Create ZIP archive
Compress-Archive -Path "$releaseDir/*" -DestinationPath $zipFile -Force

Write-Host "Release package created: $zipFile"
