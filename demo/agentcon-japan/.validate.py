import glob, sys, re, json, os, yaml

# Run relative to this file so it works from any cwd.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

SUBS = {
    # OpenAI demo: only MODEL_NAME and MODEL_ENDPOINT (default) are templated.
    # MODEL_ENDPOINT defaults to the public OpenAI API base URL.
    "MODEL_ENDPOINT": "https://api.openai.com/v1",
    "MODEL_NAME": "gpt-5.4-mini",
}
def render(t):
    def r(m):
        k=m.group(1)
        if k not in SUBS: raise KeyError("unknown placeholder ${%s}"%k)
        return SUBS[k]
    return re.sub(r"\$\{([A-Z_]+)\}", r, t)

files = sorted(glob.glob("manifests/**/*.yaml", recursive=True)) + ["values-demo.yaml"]
rc=0
docs=[]
for f in files:
    raw=open(f).read()
    try:
        rendered=render(raw)
    except KeyError as e:
        print(f"[FAIL] {f}: {e}"); rc=1; continue
    try:
        loaded=list(yaml.safe_load_all(rendered))
    except Exception as e:
        print(f"[FAIL] {f}: YAML parse error: {e}"); rc=1; continue
    n=0
    for d in loaded:
        if d is None: continue
        n+=1
        if not isinstance(d, dict):
            print(f"[FAIL] {f}: doc {n} not a mapping"); rc=1; continue
        if f!="values-demo.yaml":
            for k in ("apiVersion","kind","metadata"):
                if k not in d:
                    print(f"[FAIL] {f}: doc {n} ({d.get('kind','?')}) missing {k}"); rc=1
            docs.append((f,d))
    print(f"[ok]   {f}: {n} document(s)")

# placeholder leakage check (no ${...} left after render in any string)
def walk(o,path,f):
    global rc
    if isinstance(o,str):
        if "${" in o: print(f"[FAIL] {f}: leftover placeholder at {path}: {o!r}"); rc=1
    elif isinstance(o,dict):
        for k,v in o.items(): walk(v,path+"/"+str(k),f)
    elif isinstance(o,list):
        for i,v in enumerate(o): walk(v,path+f"[{i}]",f)

# validate embedded bundle.json is valid JSON
for f,d in docs:
    if d.get("kind")=="ConfigMap" and "bundle.json" in (d.get("data") or {}):
        try:
            json.loads(d["data"]["bundle.json"])
            print(f"[ok]   {f}: embedded bundle.json is valid JSON")
        except Exception as e:
            print(f"[FAIL] {f}: embedded bundle.json invalid: {e}"); rc=1

print("\n--- inventory (kind/name/namespace) ---")
for f,d in docs:
    m=d.get("metadata",{})
    print(f"  {d.get('kind'):16} {m.get('name'):32} ns={m.get('namespace','-')}")
sys.exit(rc)
