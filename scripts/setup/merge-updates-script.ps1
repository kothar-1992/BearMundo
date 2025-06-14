# Automated Merge Script for Bear Mod Fix Project
# Usage: .\merge-updates-script.ps1 [source_path]

param (
    [string]$sourcePath = "C:\Main Source\BearProject2023"
)

$destinationPath = $PSScriptRoot
$logFile = "$destinationPath\merge-log.txt"

function Write-Log {
    param (
        [string]$message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
    Write-Host $message
}

function Backup-Project {
    $backupFolder = "$destinationPath\backups\$(Get-Date -Format 'yyyy-MM-dd_HHmmss')"
    Write-Log "Creating backup at $backupFolder"
    
    if (!(Test-Path "$destinationPath\backups")) {
        New-Item -ItemType Directory -Path "$destinationPath\backups" | Out-Null
    }
    
    New-Item -ItemType Directory -Path $backupFolder | Out-Null
    Copy-Item -Path "$destinationPath\app" -Destination "$backupFolder\app" -Recurse
    Copy-Item -Path "$destinationPath\gradle*" -Destination $backupFolder -Recurse
    Copy-Item -Path "$destinationPath\build.gradle*" -Destination $backupFolder -Recurse
    
    Write-Log "Backup completed"
}

function Merge-JavaFiles {
    Write-Log "Merging Java files..."
    
    $sourceJavaPath = "$sourcePath\app\src\main\java\com\bearmod"
    $destJavaPath = "$destinationPath\app\src\main\java\com\bearmod"
    
    if (!(Test-Path $sourceJavaPath)) {
        Write-Log "Source Java path not found: $sourceJavaPath"
        return
    }
    
    if (!(Test-Path $destJavaPath)) {
        New-Item -ItemType Directory -Path $destJavaPath -Force | Out-Null
    }
    
    # Get list of Java files to merge
    $javaFiles = Get-ChildItem -Path $sourceJavaPath -Filter "*.java"
    
    foreach ($file in $javaFiles) {
        $destFile = "$destJavaPath\$($file.Name)"
        
        # Skip NativeUtils.java as it has issues
        if ($file.Name -eq "NativeUtils.java") {
            Write-Log "Skipping problematic file: $($file.Name)"
            continue
        }
        
        if (Test-Path $destFile) {
            # File exists, create a backup
            Copy-Item -Path $destFile -Destination "$destFile.bak" -Force
        }
        
        try {
            Copy-Item -Path $file.FullName -Destination $destFile -Force
            Write-Log "Merged: $($file.Name)"
        }
        catch {
            Write-Log "Error merging $($file.Name): $_"
        }
    }
    
    Write-Log "Java files merge completed"
}

function Merge-CppFiles {
    Write-Log "Merging C++ files..."
    
    $sourceCppPath = "$sourcePath\app\src\main\cpp"
    $destCppPath = "$destinationPath\app\src\main\cpp"
    
    if (!(Test-Path $sourceCppPath)) {
        Write-Log "Source C++ path not found: $sourceCppPath"
        return
    }
    
    if (!(Test-Path $destCppPath)) {
        New-Item -ItemType Directory -Path $destCppPath -Force | Out-Null
    }
    
    # Copy directories first
    $cppDirs = @("Helper", "Substrate", "curl", "KittyMemory", "base64", "Engine", "SDK", "TEAMNRG", "Time")
    
    foreach ($dir in $cppDirs) {
        $sourceDir = "$sourceCppPath\$dir"
        $destDir = "$destCppPath\$dir"
        
        if (Test-Path $sourceDir) {
            if (Test-Path $destDir) {
                # Directory exists, create a backup
                if (Test-Path "$destDir.bak") {
                    Remove-Item -Path "$destDir.bak" -Recurse -Force
                }
                Rename-Item -Path $destDir -NewName "$dir.bak"
            }
            
            try {
                Copy-Item -Path $sourceDir -Destination $destCppPath -Recurse -Force
                Write-Log "Merged directory: $dir"
            }
            catch {
                Write-Log "Error merging directory $dir: $_"
            }
        }
        else {
            Write-Log "Source directory not found: $dir"
        }
    }
    
    # Copy individual C++ files
    $cppFiles = @("Main.cpp", "Tools.cpp", "Tools.h", "md5.cpp", "md5.h", "MemManager.cpp", "MemManager.h")
    
    foreach ($file in $cppFiles) {
        $sourceFile = "$sourceCppPath\$file"
        $destFile = "$destCppPath\$file"
        
        if (Test-Path $sourceFile) {
            if (Test-Path $destFile) {
                # File exists, create a backup
                Copy-Item -Path $destFile -Destination "$destFile.bak" -Force
            }
            
            try {
                Copy-Item -Path $sourceFile -Destination $destFile -Force
                Write-Log "Merged: $file"
            }
            catch {
                Write-Log "Error merging $file: $_"
            }
        }
        else {
            Write-Log "Source file not found: $file"
        }
    }
    
    # Special handling for CMakeLists.txt - we'll keep our fixed version
    $destCMake = "$destCppPath\CMakeLists.txt"
    
    if (Test-Path $destCMake) {
        Write-Log "Keeping fixed CMakeLists.txt"
    }
    else {
        Copy-Item -Path "fixed-CMakeLists.txt" -Destination $destCMake -Force
        Write-Log "Copied fixed CMakeLists.txt"
    }
    
    Write-Log "C++ files merge completed"
}

function Merge-ResourceFiles {
    Write-Log "Merging resource files..."
    
    $sourceResPath = "$sourcePath\app\src\main\res"
    $destResPath = "$destinationPath\app\src\main\res"
    
    if (!(Test-Path $sourceResPath)) {
        Write-Log "Source resources path not found: $sourceResPath"
        return
    }
    
    if (!(Test-Path $destResPath)) {
        New-Item -ItemType Directory -Path $destResPath -Force | Out-Null
    }
    
    # Get list of resource directories
    $resDirs = Get-ChildItem -Path $sourceResPath -Directory
    
    foreach ($dir in $resDirs) {
        $destDir = "$destResPath\$($dir.Name)"
        
        if (Test-Path $destDir) {
            # Directory exists, create a backup
            if (Test-Path "$destDir.bak") {
                Remove-Item -Path "$destDir.bak" -Recurse -Force
            }
            Rename-Item -Path $destDir -NewName "$($dir.Name).bak"
        }
        
        try {
            Copy-Item -Path $dir.FullName -Destination $destResPath -Recurse -Force
            Write-Log "Merged resource directory: $($dir.Name)"
        }
        catch {
            Write-Log "Error merging resource directory $($dir.Name): $_"
        }
    }
    
    Write-Log "Resource files merge completed"
}

function Merge-ManifestFile {
    Write-Log "Merging AndroidManifest.xml..."
    
    $sourceManifest = "$sourcePath\app\src\main\AndroidManifest.xml"
    $destManifest = "$destinationPath\app\src\main\AndroidManifest.xml"
    
    if (!(Test-Path $sourceManifest)) {
        Write-Log "Source manifest not found: $sourceManifest"
        return
    }
    
    if (Test-Path $destManifest) {
        Copy-Item -Path $destManifest -Destination "$destManifest.bak" -Force
    }
    
    try {
        Copy-Item -Path $sourceManifest -Destination $destManifest -Force
        Write-Log "Merged: AndroidManifest.xml"
    }
    catch {
        Write-Log "Error merging AndroidManifest.xml: $_"
    }
}

function Test-Build {
    Write-Log "Testing build..."
    
    $currentLocation = Get-Location
    Set-Location $destinationPath
    
    try {
        $buildOutput = & ./gradlew clean assembleDebug 2>&1
        $buildSuccess = $LASTEXITCODE -eq 0
        
        if ($buildSuccess) {
            Write-Log "Build successful!"
        }
        else {
            Write-Log "Build failed with exit code: $LASTEXITCODE"
            Write-Log "Build output: $buildOutput"
        }
        
        return $buildSuccess
    }
    catch {
        Write-Log "Error during build: $_"
        return $false
    }
    finally {
        Set-Location $currentLocation
    }
}

function Restore-Backup {
    param (
        [string]$component
    )
    
    Write-Log "Restoring backup for $component..."
    
    switch ($component) {
        "java" {
            $destJavaPath = "$destinationPath\app\src\main\java\com\bearmod"
            $backupFiles = Get-ChildItem -Path $destJavaPath -Filter "*.bak"
            
            foreach ($file in $backupFiles) {
                $originalFile = $file.FullName -replace "\.bak$", ""
                Copy-Item -Path $file.FullName -Destination $originalFile -Force
                Remove-Item -Path $file.FullName -Force
            }
        }
        "cpp" {
            $destCppPath = "$destinationPath\app\src\main\cpp"
            
            # Restore directories
            $backupDirs = Get-ChildItem -Path $destCppPath -Directory -Filter "*.bak"
            
            foreach ($dir in $backupDirs) {
                $originalDir = $dir.FullName -replace "\.bak$", ""
                if (Test-Path $originalDir) {
                    Remove-Item -Path $originalDir -Recurse -Force
                }
                Rename-Item -Path $dir.FullName -NewName ($dir.Name -replace "\.bak$", "")
            }
            
            # Restore files
            $backupFiles = Get-ChildItem -Path $destCppPath -Filter "*.bak" -File
            
            foreach ($file in $backupFiles) {
                $originalFile = $file.FullName -replace "\.bak$", ""
                Copy-Item -Path $file.FullName -Destination $originalFile -Force
                Remove-Item -Path $file.FullName -Force
            }
        }
        "res" {
            $destResPath = "$destinationPath\app\src\main\res"
            $backupDirs = Get-ChildItem -Path $destResPath -Directory -Filter "*.bak"
            
            foreach ($dir in $backupDirs) {
                $originalDir = $dir.FullName -replace "\.bak$", ""
                if (Test-Path $originalDir) {
                    Remove-Item -Path $originalDir -Recurse -Force
                }
                Rename-Item -Path $dir.FullName -NewName ($dir.Name -replace "\.bak$", "")
            }
        }
        "manifest" {
            $destManifest = "$destinationPath\app\src\main\AndroidManifest.xml"
            $backupManifest = "$destManifest.bak"
            
            if (Test-Path $backupManifest) {
                Copy-Item -Path $backupManifest -Destination $destManifest -Force
                Remove-Item -Path $backupManifest -Force
            }
        }
    }
    
    Write-Log "Backup restored for $component"
}

function Commit-Changes {
    param (
        [string]$message
    )
    
    Write-Log "Committing changes to Git..."
    
    $currentLocation = Get-Location
    Set-Location $destinationPath
    
    try {
        git add .
        git commit -m $message
        git push
        
        Write-Log "Changes committed and pushed to GitHub"
    }
    catch {
        Write-Log "Error committing changes: $_"
    }
    finally {
        Set-Location $currentLocation
    }
}

# Main execution
Write-Log "Starting merge process from $sourcePath to $destinationPath"

# Create a backup of the current project
Backup-Project

# Merge components one by one
Merge-JavaFiles
$javaBuildSuccess = Test-Build

if (-not $javaBuildSuccess) {
    Write-Log "Java merge failed, restoring backup"
    Restore-Backup -component "java"
}
else {
    Commit-Changes -message "Merged Java files from original project"
}

Merge-CppFiles
$cppBuildSuccess = Test-Build

if (-not $cppBuildSuccess) {
    Write-Log "C++ merge failed, restoring backup"
    Restore-Backup -component "cpp"
}
else {
    Commit-Changes -message "Merged C++ files from original project"
}

Merge-ResourceFiles
$resBuildSuccess = Test-Build

if (-not $resBuildSuccess) {
    Write-Log "Resource merge failed, restoring backup"
    Restore-Backup -component "res"
}
else {
    Commit-Changes -message "Merged resource files from original project"
}

Merge-ManifestFile
$manifestBuildSuccess = Test-Build

if (-not $manifestBuildSuccess) {
    Write-Log "Manifest merge failed, restoring backup"
    Restore-Backup -component "manifest"
}
else {
    Commit-Changes -message "Merged AndroidManifest.xml from original project"
}

Write-Log "Merge process completed"
