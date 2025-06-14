# Enhanced Merge Script for Bear Mod Fix Project
# This script can download and build missing components

param (
    [string]$sourcePath = "C:\Main Source\BearProject2023",
    [switch]$downloadMissing = $false
)

$destinationPath = $PSScriptRoot
$logFile = "$destinationPath\merge-log.txt"
$dependenciesPath = "$destinationPath\dependencies"

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

function Check-Dependencies {
    Write-Log "Checking for required dependencies..."
    
    # Check for NDK
    $ndkPath = "$env:ANDROID_HOME\ndk"
    if (!(Test-Path $ndkPath)) {
        Write-Log "Android NDK not found at $ndkPath"
        
        if ($downloadMissing) {
            Write-Log "Attempting to download NDK..."
            try {
                # Use sdkmanager to install NDK
                $sdkManagerPath = "$env:ANDROID_HOME\tools\bin\sdkmanager.bat"
                if (Test-Path $sdkManagerPath) {
                    & $sdkManagerPath "ndk;21.4.7075529" | Out-Null
                    Write-Log "NDK installed successfully"
                }
                else {
                    Write-Log "SDK Manager not found, cannot install NDK automatically"
                    return $false
                }
            }
            catch {
                Write-Log "Failed to install NDK: $_"
                return $false
            }
        }
        else {
            Write-Log "Use -downloadMissing switch to automatically download NDK"
            return $false
        }
    }
    
    # Check for required C++ libraries
    $requiredLibs = @("curl", "openssl")
    $missingLibs = @()
    
    foreach ($lib in $requiredLibs) {
        $libPath = "$destinationPath\app\src\main\cpp\$lib"
        if (!(Test-Path $libPath)) {
            $missingLibs += $lib
        }
    }
    
    if ($missingLibs.Count -gt 0) {
        Write-Log "Missing libraries: $($missingLibs -join ', ')"
        
        if ($downloadMissing) {
            foreach ($lib in $missingLibs) {
                Download-Library -name $lib
            }
        }
        else {
            Write-Log "Use -downloadMissing switch to automatically download missing libraries"
            return $false
        }
    }
    
    return $true
}

function Download-Library {
    param (
        [string]$name
    )
    
    Write-Log "Downloading $name library..."
    
    if (!(Test-Path $dependenciesPath)) {
        New-Item -ItemType Directory -Path $dependenciesPath -Force | Out-Null
    }
    
    $libPath = "$destinationPath\app\src\main\cpp\$name"
    if (!(Test-Path $libPath)) {
        New-Item -ItemType Directory -Path $libPath -Force | Out-Null
    }
    
    switch ($name) {
        "curl" {
            $curlUrl = "https://curl.se/download/curl-7.86.0.zip"
            $curlZip = "$dependenciesPath\curl.zip"
            
            try {
                Invoke-WebRequest -Uri $curlUrl -OutFile $curlZip
                Expand-Archive -Path $curlZip -DestinationPath "$dependenciesPath\curl" -Force
                
                # Copy required files to the project
                Copy-Item -Path "$dependenciesPath\curl\curl-7.86.0\include" -Destination "$libPath\curl-android-arm64-v8a" -Recurse -Force
                
                Write-Log "Downloaded and extracted curl library"
            }
            catch {
                Write-Log "Failed to download curl: $_"
            }
        }
        "openssl" {
            $opensslUrl = "https://www.openssl.org/source/openssl-3.0.7.tar.gz"
            $opensslTar = "$dependenciesPath\openssl.tar.gz"
            
            try {
                Invoke-WebRequest -Uri $opensslUrl -OutFile $opensslTar
                
                # Extract tar.gz file
                if (Get-Command tar -ErrorAction SilentlyContinue) {
                    tar -xzf $opensslTar -C $dependenciesPath
                }
                else {
                    Write-Log "tar command not found, cannot extract openssl"
                    return
                }
                
                # Copy required files to the project
                Copy-Item -Path "$dependenciesPath\openssl-3.0.7\include" -Destination "$libPath\openssl-android-arm64-v8a" -Recurse -Force
                
                Write-Log "Downloaded and extracted openssl library"
            }
            catch {
                Write-Log "Failed to download openssl: $_"
            }
        }
    }
}

function Merge-JavaFiles {
    Write-Log "Merging Java files..."
    
    $sourceJavaPath = "$sourcePath\app\src\main\java\com\bearmod"
    $destJavaPath = "$destinationPath\app\src\main\java\com\bearmod"
    
    if (!(Test-Path $sourceJavaPath)) {
        Write-Log "Source Java path not found: $sourceJavaPath"
        
        if ($downloadMissing) {
            Write-Log "Creating basic Java structure..."
            if (!(Test-Path $destJavaPath)) {
                New-Item -ItemType Directory -Path $destJavaPath -Force | Out-Null
            }
            
            # Copy fixed NativeUtils.java
            Copy-Item -Path "fixed-NativeUtils.java" -Destination "$destJavaPath\NativeUtils.java" -Force
            Write-Log "Created basic Java structure with fixed NativeUtils.java"
        }
        
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
            
            # Use our fixed version instead
            Copy-Item -Path "fixed-NativeUtils.java" -Destination "$destJavaPath\NativeUtils.java" -Force
            Write-Log "Copied fixed NativeUtils.java"
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
        
        if ($downloadMissing) {
            Write-Log "Creating basic C++ structure..."
            if (!(Test-Path $destCppPath)) {
                New-Item -ItemType Directory -Path $destCppPath -Force | Out-Null
            }
            
            # Copy fixed CMakeLists.txt
            Copy-Item -Path "fixed-CMakeLists.txt" -Destination "$destCppPath\CMakeLists.txt" -Force
            
            # Create a basic Main.cpp file if it doesn't exist
            if (!(Test-Path "$destCppPath\Main.cpp")) {
                @"
#include <jni.h>
#include <string>
#include <android/log.h>

#define TAG "BearMod"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetOnlineName(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("Bear Mod");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetChannelInfo(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("Channel Info");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetFeedbackInfo(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("Feedback Info");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetIconData(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bearmod_NativeUtils_nativeGetConfig(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("{}");
}

extern "C" JNIEXPORT void JNICALL
Java_com_bearmod_NativeUtils_nativeSwitch(JNIEnv *env, jclass clazz, jint value) {
    LOGD("Switch value: %d", value);
}

extern "C" JNIEXPORT void JNICALL
Java_com_bearmod_NativeUtils_nativeDrawOn(JNIEnv *env, jclass clazz, jobject esp_view, jobject canvas) {
    LOGD("Drawing on canvas");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_bearmod_NativeUtils_nativeIsEspHidden(JNIEnv *env, jclass clazz) {
    return false;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("JNI_OnLoad called");
    return JNI_VERSION_1_6;
}
"@ | Out-File -FilePath "$destCppPath\Main.cpp" -Encoding utf8
                Write-Log "Created basic Main.cpp file"
            }
            
            Write-Log "Created basic C++ structure"
        }
        
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
        
        if ($downloadMissing) {
            Write-Log "Creating basic resource structure..."
            if (!(Test-Path $destResPath)) {
                New-Item -ItemType Directory -Path $destResPath -Force | Out-Null
            }
            
            # Create basic resource directories
            $basicResDirs = @("drawable", "layout", "values")
            foreach ($dir in $basicResDirs) {
                $resDir = "$destResPath\$dir"
                if (!(Test-Path $resDir)) {
                    New-Item -ItemType Directory -Path $resDir -Force | Out-Null
                }
            }
            
            # Create a basic strings.xml file
            @"
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Bear Mod</string>
</resources>
"@ | Out-File -FilePath "$destResPath\values\strings.xml" -Encoding utf8
            
            Write-Log "Created basic resource structure"
        }
        
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
        
        if ($downloadMissing) {
            Write-Log "Creating basic AndroidManifest.xml..."
            
            $manifestDir = "$destinationPath\app\src\main"
            if (!(Test-Path $manifestDir)) {
                New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
            }
            
            # Create a basic AndroidManifest.xml file
            @"
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.bearmod">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
"@ | Out-File -FilePath $destManifest -Encoding utf8
            
            Write-Log "Created basic AndroidManifest.xml"
        }
        
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
Write-Log "Starting enhanced merge process from $sourcePath to $destinationPath"
Write-Log "Auto-download missing components: $downloadMissing"

# Check dependencies
$dependenciesOk = Check-Dependencies
if (-not $dependenciesOk) {
    Write-Log "Dependencies check failed. Use -downloadMissing switch to automatically download missing components."
    if (-not $downloadMissing) {
        exit 1
    }
}

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

Write-Log "Enhanced merge process completed"
