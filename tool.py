#!/usr/bin/env python3
"""Resolve links using an in-tree metadata inventory, never external targets."""
from collections import deque
import os
import stat
from _support import Parser, Report, anchored, cli, guarded, limits, positive, walk
TOOL="symlink-scope-audit"

def resolve_link(path, entries, root_parts, max_hops):
    pending=deque(path.split("/"));stack=[];visited=set();hops=0
    while pending:
        part=pending.popleft()
        if part in ("", "."):continue
        if part=="..":
            if not stack:return "outside_scope",hops
            stack.pop();continue
        key="/".join(stack+[part])
        entry=entries.get(key)
        if entry is None:return "dangling_link",hops
        kind,target=entry
        if kind=="symlink":
            state=(key,tuple(pending))
            if state in visited:return "symlink_cycle",hops
            visited.add(state);hops+=1
            if hops>max_hops:return "link_hop_limit_exceeded",hops
            if target.startswith("/"):
                tokens=deque(target.split("/")[1:])
                # Ignore harmless separators/dots only while matching the real
                # root prefix. Never normalize away '..', and keep the suffix
                # verbatim so file/. and file/ still require a directory.
                for root_part in root_parts:
                    while tokens and tokens[0] in ("", "."):tokens.popleft()
                    if not tokens or tokens.popleft()!=root_part:return "outside_scope",hops
                stack=[]
            else:tokens=target.split("/")
            pending.extendleft(reversed(tokens))
        else:
            stack.append(part)
            if pending and kind!="directory":return "non_directory_component",hops
    return None,hops

@guarded(TOOL)
def audit(root, *, max_entries=100000,max_depth=64,max_hops=64,max_findings=1000):
    limits(max_entries=max_entries,max_depth=max_depth,max_hops=max_hops,max_findings=max_findings)
    report=Report(TOOL,max_findings);entries={};links=[]
    with anchored(root,True) as fd:
        for rel,st,parent,name in walk(fd,max_entries,max_depth):
            if stat.S_ISLNK(st.st_mode):
                entries[rel]=("symlink",os.readlink(name,dir_fd=parent));links.append(rel)
            else:entries[rel]=("directory" if stat.S_ISDIR(st.st_mode) else "entry",None)
    root_parts=[p for p in os.path.abspath(root).split("/") if p]
    checked=0
    for rel in sorted(links):
        code,hops=resolve_link(rel,entries,root_parts,max_hops);checked+=1
        if code:report.add(code,path=rel,link_hops=hops)
    return report.finish({"entries_scanned":len(entries),"links_checked":checked})

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument("root")
    for name,default in [("max-entries",100000),("max-depth",64),("max-hops",64),("max-findings",1000)]:p.add_argument("--"+name,type=positive,default=default)
    a=vars(p.parse_args());root=a.pop("root");return audit(root,**a)
if __name__=="__main__":raise SystemExit(cli(TOOL,parse_and_audit))
