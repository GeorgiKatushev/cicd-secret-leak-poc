#!/usr/bin/env python3
"""
Simple Secret Scanner
Scans files for common secret patterns using regex.
Exits with code 1 if any secrets are found.
"""

import os
import re
import sys

# --- Secret patterns to scan for ---
PATTERNS = {
    "AWS Access Key":     r"AKIA[0-9A-Z]{16}",
    "GitHub Token":       r"ghp_[A-Za-z0-9]{36}",
    "Private Key":        r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----",
    "Generic API Key":    r"(?i)api[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{20,}",
    "Password in code":   r"(?i)password\s*=\s*['\"]?\S{6,}",
}

# --- Extensions to skip (binary files) ---
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe"}

# --- Specific files to skip ---
SKIP_FILES = {
    "trufflehog-config.yaml",
    ".pre-commit-config.yaml",
    "exclude-patterns.txt",
    "scanner.py",
}

# --- Directories to skip ---
SKIP_DIRS = {".git"}

findings = []


def scan_file(filepath):
    """Scan a single file line by line against all patterns."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for secret_type, pattern in PATTERNS.items():
                    if re.search(pattern, line):
                        findings.append({
                            "type":    secret_type,
                            "file":    filepath,
                            "line":    line_num,
                            "content": line.strip()
                        })
    except Exception as e:
        print(f"[SKIP] Could not read {filepath}: {e}")


def scan_directory(target):
    """Walk a directory and scan every non-binary file."""
    for root, dirs, files in os.walk(target):
        # Skip unwanted directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            # Skip unwanted files
            if filename in SKIP_FILES:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SKIP_EXTENSIONS:
                scan_file(os.path.join(root, filename))


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    print(f"\n🔍 Scanning: {target}\n")

    if os.path.isfile(target):
        scan_file(target)
    else:
        scan_directory(target)

    # --- Report results ---
    if findings:
        print(f"❌ Found {len(findings)} potential secret(s):\n")
        for f in findings:
            print(f"  [{f['type']}]")
            print(f"  File : {f['file']}")
            print(f"  Line : {f['line']}")
            print(f"  Code : {f['content']}")
            print()
        sys.exit(1)
    else:
        print("✅ No secrets found.")
        sys.exit(0)


if __name__ == "__main__":
    main()