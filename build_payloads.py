import os
import glob
from pathlib import Path

repo = Path("payload_tmp")
dest = Path(r"src\secagents\data\payloads")

mappings = {
    "xss.txt": ["XSS Injection/Intruders/*.txt", "XSS Injection/*.txt"],
    "sqli.txt": ["SQL Injection/Intruders/*.txt"],
    "ssrf.txt": ["Server Side Request Forgery/Intruders/*.txt"],
    "xxe.txt": ["XXE Injection/Intruders/*.txt", "XXE Injection/*.txt"],
    "ssti.txt": ["Server Side Template Injection/Intruders/*.txt", "Server Side Template Injection/*.txt"],
    "lfi.txt": ["File Inclusion/Intruders/*.txt", "Directory Traversal/Intruders/*.txt"],
    "open_redirect.txt": ["Open Redirect/Intruders/*.txt", "Open Redirect/*.txt"],
    "idor.txt": ["Insecure Direct Object Reference/Intruders/*.txt", "Insecure Direct Object Reference/*.txt"],
    "jwt.txt": ["JSON Web Token/Intruders/*.txt", "JSON Web Token/*.txt"],
    "prompt_injection.txt": ["Prompt Injection/Intruders/*.txt", "Prompt Injection/*.txt", "LLM Injection/*.txt"],
}

for out_name, globs in mappings.items():
    out_path = dest / out_name
    existing = set()
    if out_path.exists():
        with out_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    existing.add(line.strip())
                    
    collected = []
    for g in globs:
        for fpath in repo.rglob(g.split('/')[-1]):
            # ensure it's in the right parent dir
            if g.split('/')[0] in str(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            l = line.strip()
                            if l and not l.startswith('#') and l not in existing:
                                existing.add(l)
                                collected.append(l)
                except Exception as e:
                    pass
    
    if collected:
        with out_path.open("a", encoding="utf-8") as f:
            f.write("\n# Imported from PayloadsAllTheThings\n")
            for c in collected:
                f.write(c + "\n")
        print(f"Added {len(collected)} payloads to {out_name}")
    else:
        print(f"No new payloads for {out_name}")
