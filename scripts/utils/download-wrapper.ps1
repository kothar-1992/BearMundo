$wrapperJarPath = "gradle\wrapper\gradle-wrapper.jar"
$wrapperUrl = "https://github.com/gradle/gradle/raw/master/gradle/wrapper/gradle-wrapper.jar"

Write-Host "Downloading Gradle wrapper JAR file..."
Invoke-WebRequest -Uri $wrapperUrl -OutFile $wrapperJarPath

if (Test-Path $wrapperJarPath) {
    Write-Host "Successfully downloaded Gradle wrapper JAR to $wrapperJarPath"
} else {
    Write-Host "Failed to download Gradle wrapper JAR"
}
