# Setup for Existing GitHub Repository for Bear Mod Fix
# This script initializes a Git repository and pushes it to your existing GitHub repo

# Configuration
$repoUrl = "https://github.com/ZeusOwner/Bear-Mod-Fix.git"
$userName = "ZeusOwner"
$userEmail = "kothihawailwin@gmail.com"
$projectPath = "C:\Fix-CMake"

# Navigate to project directory
Set-Location $projectPath

# Initialize Git repository
Write-Host "Initializing Git repository..." -ForegroundColor Green
git init

# Configure Git user
Write-Host "Configuring Git user..." -ForegroundColor Green
git config user.name $userName
git config user.email $userEmail

# Copy the .gitignore file
Write-Host "Setting up .gitignore..." -ForegroundColor Green
Copy-Item -Path "android-gitignore.txt" -Destination ".gitignore" -Force

# Copy the README.md file
Write-Host "Setting up README.md..." -ForegroundColor Green
Copy-Item -Path "bear-mod-fix-readme.md" -Destination "README.md" -Force

# Create GitHub Actions directory
Write-Host "Setting up GitHub Actions workflow..." -ForegroundColor Green
if (!(Test-Path ".github\workflows")) {
    New-Item -ItemType Directory -Path ".github\workflows" -Force | Out-Null
}
Copy-Item -Path "github-actions-workflow.yml" -Destination ".github\workflows\android-ci.yml" -Force

# Copy the fixed CMakeLists.txt file
Write-Host "Setting up fixed CMakeLists.txt..." -ForegroundColor Green
$cmakeDir = "app\src\main\cpp"
if (!(Test-Path $cmakeDir)) {
    New-Item -ItemType Directory -Path $cmakeDir -Force | Out-Null
}
Copy-Item -Path "fixed-CMakeLists.txt" -Destination "$cmakeDir\CMakeLists.txt" -Force

# Copy the fixed NativeUtils.java file
Write-Host "Setting up fixed NativeUtils.java..." -ForegroundColor Green
$javaDir = "app\src\main\java\com\bearmod"
if (!(Test-Path $javaDir)) {
    New-Item -ItemType Directory -Path $javaDir -Force | Out-Null
}
Copy-Item -Path "fixed-NativeUtils.java" -Destination "$javaDir\NativeUtils.java" -Force

# Add all files to Git
Write-Host "Adding files to Git..." -ForegroundColor Green
git add .

# Commit changes
Write-Host "Committing changes..." -ForegroundColor Green
git commit -m "Initial commit with fixed project structure"

# Add GitHub remote
Write-Host "Adding GitHub remote..." -ForegroundColor Green
git remote add origin $repoUrl

# Push to GitHub
Write-Host "Pushing to GitHub..." -ForegroundColor Green
git push -u origin master

Write-Host "Setup complete!" -ForegroundColor Green
Write-Host "Your repository is now available at: $repoUrl" -ForegroundColor Cyan
