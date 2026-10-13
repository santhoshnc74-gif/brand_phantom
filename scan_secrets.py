import os
import re

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("Private Key Block", re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ("GitHub Personal Token", re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')),
    ("Slack API Token", re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}')),
    ("Hardcoded API Key / Secret", re.compile(r'(?i)(api[_-]?key|client[_-]?secret|jwt[_-]?secret)\s*[:=]\s*["\'](?!placeholder|your-|sandbox_)[a-zA-Z0-9_\-\.]{20,}["\']')),
]

def scan_repository():
    findings = []
    base_dir = os.path.abspath(os.path.dirname(__file__))

    for root, dirs, files in os.walk(base_dir):
        # Ignore virtual envs, git directory, cache
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".venv", "venv", "node_modules"}]
        
        for f in files:
            if f.endswith((".png", ".db", ".pyc", ".ico", ".jpg", ".svg")):
                continue
            if f in {".env.example"}: # skip example template
                continue

            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, base_dir)

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                    for line_no, line in enumerate(fp, start=1):
                        for label, regex in SECRET_PATTERNS:
                            if regex.search(line):
                                findings.append({
                                    "type": label,
                                    "file": rel_path,
                                    "line": line_no
                                })
            except Exception as e:
                pass

    return findings

if __name__ == "__main__":
    results = scan_repository()
    print("==================================================")
    print("SECRET SCANNER REPORT (Accidental Exposure Audit)")
    print("==================================================")
    if not results:
        print("RESULT: Clean. Zero accidental secrets or private keys detected in repository files.")
    else:
        print(f"RESULT: Found {len(results)} potential secret locations (Values withheld):")
        for r in results:
            print(f" - [{r['type']}] Location: {r['file']}:L{r['line']}")
