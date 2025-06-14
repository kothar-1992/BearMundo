#!/usr/bin/env python3
"""
SDK Checker Tool for BearMod Project
This script checks for missing SDK files and dependencies
"""

import os
import sys
import glob
import argparse
from pathlib import Path
import json

def check_sdk_files(sdk_path):
    """Check for critical SDK files"""
    critical_files = [
        "PUBGM_Basic.hpp",
        "PUBGM_Basic.cpp",
        "PUBGM_CoreUObject_classes.hpp",
        "PUBGM_Engine_classes.hpp",
        "PUBGM_Basic_functions.cpp",
        "PUBGM_CoreUObject_functions.cpp",
        "PUBGM_Engine_functions.cpp"
    ]
    
    missing_files = []
    for file in critical_files:
        file_path = os.path.join(sdk_path, file)
        if not os.path.exists(file_path):
            missing_files.append(file)
    
    return missing_files

def check_external_libs(project_path, abi="arm64-v8a"):
    """Check for external libraries"""
    libs_to_check = {
        "curl": os.path.join(project_path, "curl", f"curl-android-{abi}", "lib", "libcurl.a"),
        "ssl": os.path.join(project_path, "curl", f"openssl-android-{abi}", "lib", "libssl.a"),
        "crypto": os.path.join(project_path, "curl", f"openssl-android-{abi}", "lib", "libcrypto.a"),
        "dobby": os.path.join(project_path, "Helper", "Dobby", "libraries", abi, "libdobby.a")
    }
    
    missing_libs = {}
    for lib_name, lib_path in libs_to_check.items():
        if not os.path.exists(lib_path):
            missing_libs[lib_name] = lib_path
    
    return missing_libs

def check_include_paths(project_path, abi="arm64-v8a"):
    """Check for include directories"""
    include_paths = {
        "curl_include": os.path.join(project_path, "curl", f"curl-android-{abi}", "include"),
        "openssl_include": os.path.join(project_path, "curl", f"openssl-android-{abi}", "include"),
        "dobby_include": os.path.join(project_path, "Helper", "Dobby", "libraries")
    }
    
    missing_includes = {}
    for include_name, include_path in include_paths.items():
        if not os.path.exists(include_path):
            missing_includes[include_name] = include_path
    
    return missing_includes

def check_sdk_dependencies(sdk_path):
    """Check for SDK dependencies between files"""
    # Get all header files
    header_files = glob.glob(os.path.join(sdk_path, "PUBGM_*.hpp"))
    
    # Check for dependencies
    dependency_issues = []
    for header_file in header_files:
        base_name = os.path.basename(header_file)
        # Check if there's a corresponding implementation file
        if base_name.endswith("_classes.hpp"):
            impl_name = base_name.replace("_classes.hpp", "_functions.cpp")
            impl_path = os.path.join(sdk_path, impl_name)
            if not os.path.exists(impl_path):
                dependency_issues.append(f"Missing implementation file for {base_name}: {impl_name}")
    
    return dependency_issues

def generate_report(project_path, output_file=None):
    """Generate a comprehensive report"""
    sdk_path = os.path.join(project_path, "SDK")
    
    report = {
        "project_path": project_path,
        "sdk_path": sdk_path,
        "sdk_exists": os.path.exists(sdk_path),
        "missing_sdk_files": [],
        "missing_libs": {},
        "missing_includes": {},
        "dependency_issues": [],
        "recommendations": []
    }
    
    # Check if SDK directory exists
    if not report["sdk_exists"]:
        report["recommendations"].append("Create SDK directory at " + sdk_path)
    else:
        # Check for missing SDK files
        report["missing_sdk_files"] = check_sdk_files(sdk_path)
        if report["missing_sdk_files"]:
            report["recommendations"].append("Add missing SDK files: " + ", ".join(report["missing_sdk_files"]))
        
        # Check for SDK dependencies
        report["dependency_issues"] = check_sdk_dependencies(sdk_path)
        if report["dependency_issues"]:
            report["recommendations"].append("Fix SDK dependencies")
    
    # Check for external libraries
    report["missing_libs"] = check_external_libs(project_path)
    if report["missing_libs"]:
        report["recommendations"].append("Add missing libraries: " + ", ".join(report["missing_libs"].keys()))
    
    # Check for include paths
    report["missing_includes"] = check_include_paths(project_path)
    if report["missing_includes"]:
        report["recommendations"].append("Add missing include directories: " + ", ".join(report["missing_includes"].keys()))
    
    # Output report
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    return report

def print_report(report):
    """Print the report in a readable format"""
    print("\n===== SDK Checker Report =====")
    print(f"Project path: {report['project_path']}")
    print(f"SDK path: {report['sdk_path']}")
    print(f"SDK exists: {'Yes' if report['sdk_exists'] else 'No'}")
    
    if report["sdk_exists"]:
        print("\n--- Missing SDK Files ---")
        if report["missing_sdk_files"]:
            for file in report["missing_sdk_files"]:
                print(f"  - {file}")
        else:
            print("  None")
        
        print("\n--- SDK Dependency Issues ---")
        if report["dependency_issues"]:
            for issue in report["dependency_issues"]:
                print(f"  - {issue}")
        else:
            print("  None")
    
    print("\n--- Missing Libraries ---")
    if report["missing_libs"]:
        for lib_name, lib_path in report["missing_libs"].items():
            print(f"  - {lib_name}: {lib_path}")
    else:
        print("  None")
    
    print("\n--- Missing Include Directories ---")
    if report["missing_includes"]:
        for include_name, include_path in report["missing_includes"].items():
            print(f"  - {include_name}: {include_path}")
    else:
        print("  None")
    
    print("\n--- Recommendations ---")
    if report["recommendations"]:
        for i, recommendation in enumerate(report["recommendations"], 1):
            print(f"  {i}. {recommendation}")
    else:
        print("  No issues found!")
    
    print("\n==============================")

def main():
    parser = argparse.ArgumentParser(description="Check SDK files and dependencies for BearMod project")
    parser.add_argument("project_path", help="Path to the project directory")
    parser.add_argument("--output", "-o", help="Output file for JSON report")
    parser.add_argument("--abi", default="arm64-v8a", help="Android ABI (default: arm64-v8a)")
    
    args = parser.parse_args()
    
    # Validate project path
    if not os.path.exists(args.project_path):
        print(f"Error: Project path '{args.project_path}' does not exist")
        return 1
    
    # Generate report
    report = generate_report(args.project_path, args.output)
    
    # Print report
    print_report(report)
    
    # Return success if no issues found
    if not report["recommendations"]:
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
