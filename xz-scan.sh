#!/bin/bash

echo "Starting the scan..."

vulnerable_versions=("XZ_5.6.0" "XZ_5.6.1")
patched_versions=("XZ_5.6.1+really" "XZ_5.6.1-2" "XZ_5.6.1-3")

# Detect package manager
if command -v dpkg >/dev/null; then
    pkg_manager="dpkg"
elif command -v rpm >/dev/null; then
    pkg_manager="rpm"
elif command -v pacman >/dev/null; then
    pkg_manager="pacman"
else
    echo "Unsupported package manager. This script requires dpkg, rpm, or pacman."
    exit 1
fi

# Function to check xz version using package manager
check_xz_version() {
    echo "Checking xz version ..."
    case $pkg_manager in
        dpkg)
            xz_version=$(dpkg -s xz-utils 2>/dev/null | grep '^Version:' | awk '{print $2}')
            if [ -z "$xz_version" ]; then
                xz_version=$(dpkg -s xz 2>/dev/null | grep '^Version:' | awk '{print $2}')
            fi
            ;;
        rpm)
            xz_version=$(rpm -q xz --qf "%{VERSION}-%{RELEASE}\n" 2>/dev/null)
            ;;
        pacman)
            xz_version=$(pacman -Qi xz 2>/dev/null | grep '^Version' | awk '{print $3}')
            ;;
    esac

    if [ -n "$xz_version" ]; then
        echo "Detected xz version: $xz_version"
        if [[ "$xz_version" == "5.6.0"* || ("$xz_version" == "5.6.1"* && "$xz_version" != "5.6.1+really"* && "$xz_version" != "5.6.1-2"* && "$xz_version" != "5.6.1-3"*) ]]; then
            echo "System is possibly vulnerable to CVE-2024-3094"
        elif [[ "$xz_version" == "5.6.1+really"* || "$xz_version" == "5.6.1-2"* || "$xz_version" == "5.6.1-3"* ]]; then
            echo "System is probably patched against CVE-2024-3094"
        else
            echo "System is probably not vulnerable to CVE-2024-3094"
        fi
    else
        echo "Could not determine xz version using package manager"
    fi
}

scan_all_exes() {
  echo "Scanning all executables..."
  find / -type f -executable -print0 2>/dev/null | while IFS= read -r -d '' file; do
    if file "$file" | grep -q "dynamically linked"; then
        if ldd "$file" 2>/dev/null | grep -q "liblzma.so"; then
            liblzma_path=$(ldd "$file" | grep -oP 'liblzma\.so\.\d+ => \K\S+')
            if [ -n "$liblzma_path" ]; then
                lzma_versions=$(readelf -s "$liblzma_path" 2>/dev/null | grep '@@XZ_' | awk '{print $NF}' | cut -d '@' -f 3 | sort -r -u | head -n 1)
                for lzma_version in $lzma_versions; do
                    for vulnerable_version in "${vulnerable_versions[@]}"; do
                        if [[ "$lzma_version" == "$vulnerable_version" ]]; then
                            echo "WARNING: $file is linked with vulnerable liblzma version $vulnerable_version"
                        fi
                    done
                    for patched_version in "${patched_versions[@]}"; do
                        if [[ "$lzma_version" == "$patched_version" ]]; then
                            echo "INFO: $file is linked with patched liblzma version $patched_version"
                        fi
                    done
                done
            fi
        fi
    fi
  done
}

check_xz_version

scan_all_exes

echo "Scan complete."