# SecureCode AI — Source-to-Sink Taint & Dataflow Analysis

## 1. Overview

Taint Analysis tracks user-controlled, untrusted data flows from external entry points (**Sources**) through intermediate variable assignments, operations, and string transformations (**Transforms**) into security-critical execution points (**Sinks**).

---

## 2. Architecture & Components

```
+-----------------------------------------------------------------------------+
|                          TAINT ANALYSIS ENGINE                              |
+-----------------------------------------------------------------------------+
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       ▼                              ▼                              ▼
+───────────────+              +───────────────+              +───────────────+
| SourceRegistry|              |  TaintPropag  |              |  SinkRegistry |
| Entry Points  |              |  Expressions  |              | Critical APIs |
+───────────────+              +───────────────+              +───────────────+
       │                              │                              │
       └──────────────────────────────┼──────────────────────────────┘
                                      ▼
                        +───────────────────────────+
                        |      DataFlowGraph        |
                        | Directed Taint Propagation|
                        +───────────────────────────+
                                      │
                                      ▼
                        +───────────────────────────+
                        |     SanitizerRegistry     |
                        | Context-Specific Guards   |
                        +───────────────────────────+
                                      │
                                      ▼
                        +───────────────────────────+
                        |  Multi-Step Taint Finding |
                        | [SOURCE -> TRANSFORM ->   |
                        |  SINK] Dataflow Evidence  |
                        +───────────────────────────+
```

---

## 3. Sources, Sinks, and Verified Sanitizers

### 3.1 Input Sources (`SourceRegistry`)
- **HTTP Parameters**: `request.args.get()`, `request.form.get()`, `request.values.get()`, `request.GET.get()`, `request.POST.get()`, `request.query_params.get()`.
- **Request Bodies**: `request.json`, `request.data`, `request.body`.
- **System & Console Inputs**: `sys.argv`, `input()`, `sys.stdin.read()`.
- **DOM & Client Inputs (JS)**: `urlParams.get()`, `location.search`, `location.hash`, `req.query`, `req.body`, `document.cookie`.

### 3.2 Execution Sinks (`SinkRegistry`)
- **SQL Execution**: `cursor.execute()`, `executemany()`, `raw_sql()`.
- **OS Shell**: `os.system()`, `os.popen()`, `subprocess.run(..., shell=True)`, `child_process.exec()`.
- **File System**: `open()`, `send_file()`, `fs.readFile()`.
- **Object Deserializers**: `pickle.loads()`, `pickle.load()`, `yaml.load()`.
- **DOM Markup**: `innerHTML`, `outerHTML`, `document.write`.
- **Code Evaluation**: `eval()`, `exec()`, `new Function()`.

### 3.3 Strict Sanitizers (`SanitizerRegistry`)
> [!IMPORTANT]
> SecureCode AI **does not** accept functions simply because their name contains the word `sanitize`. Only mathematically and structurally verified defenses are recognized:
- **CWE-89 (SQLi)**: Type casting via `int()` / `float()`, parameterized prepared statements (`?`, `%s`).
- **CWE-78 (Cmd Injection)**: `shlex.quote()`, parameter array separation with `shell=False`.
- **CWE-22 (Path Traversal)**: `os.path.basename()`, `pathlib.Path.name`, `secure_filename()`, canonical prefix verification (`abspath(target).startswith(BASE_DIR)`).
- **CWE-79 (XSS)**: `html.escape()`, `markupsafe.escape()`, `DOMPurify.sanitize()`, `encodeURIComponent()`.
- **CWE-502 (Deserialization)**: `json.loads()`, `yaml.safe_load()`, `ast.literal_eval()`.

---

## 4. Example Source-to-Sink Trace

When analyzing vulnerable code:
```python
username = request.args.get("username")
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)
```

The engine produces a verified 3-step `dataFlow` evidence chain:

1. **Step 1 (SOURCE)**:
   - Line: 2
   - Snippet: `username = request.args.get("username")`
   - Description: Untrusted user input enters system via Flask query parameter.
2. **Step 2 (TRANSFORM)**:
   - Line: 3
   - Snippet: `query = "SELECT * FROM users WHERE name = '" + username + "'"`
   - Description: Untrusted variable `username` incorporated into execution string via dynamic string concatenation.
3. **Step 3 (SINK)**:
   - Line: 4
   - Snippet: `cursor.execute(query)`
   - Description: Tainted query string dispatched to database cursor without parameterized bindings.
