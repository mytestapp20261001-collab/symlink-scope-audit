"""Synthetic examples; all fixtures live in an automatically removed temporary directory."""
from pathlib import Path
import json, subprocess, sys, tempfile
TOOL=Path(__file__).resolve().parents[1]/"tool.py"
def run(expected,*args):
    r=subprocess.run([sys.executable,str(TOOL),*map(str,args)],capture_output=True,text=True)
    assert r.returncode==expected,(r.returncode,r.stdout,r.stderr)
    print(r.stdout.strip())
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)
    (p/"file.txt").write_text("synthetic\n");(p/"link").symlink_to("file.txt")
    run(0,p);(p/"outside").symlink_to("../outside-scope");run(1,p)
