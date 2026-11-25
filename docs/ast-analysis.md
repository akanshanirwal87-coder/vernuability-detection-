# SecureCode AI — Abstract Syntax Tree (AST) Security Analysis

## 1. Overview

SecureCode AI employs Abstract Syntax Tree (AST) parsing to structurally inspect source code for security-sensitive operations, dangerous execution sinks, and unsafe dynamic string constructions without compiling or executing untrusted files.

---

## 2. Supported Languages & Parsing Strategy

### Python AST Inspection (`backend/analyzer/python_ast_scanner.py`)
- Utilizes Python's native `ast` standard library (`ast.parse`).
- Traverses code trees using structured node walkers and two-pass analysis:
  - **First Pass (Metadata & Symbol Discovery)**: Discovers imports (`ast.Import`, `ast.ImportFrom`), function definitions (`ast.FunctionDef`), and variable assignments (`ast.Assign`) to build an in-memory symbol map.
  - **Second Pass (Security Sinks & Pattern Matching)**: Evaluates function call expressions (`ast.Call`), attribute accesses (`ast.Attribute`), binary operations (`ast.BinOp`), and f-strings (`ast.JoinedStr`) against registered security vulnerabilities.

### JavaScript AST Inspection (`backend/analyzer/javascript_scanner.py`)
- Employs lexical tokenization, regex-based statement extraction, and structural AST-like node generation.
- Inspects DOM writes, client-side execution sinks, property chains (`__proto__`), and Node.js child process invocations.

---

## 3. Supported Vulnerability Patterns

| Vulnerability Category | CWE Identifier | OWASP Category | Target Sinks / Patterns |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | **CWE-89** | A03:2021-Injection | `cursor.execute()`, `executemany()`, `raw()` with dynamic strings |
| **Command Injection** | **CWE-78** | A03:2021-Injection | `os.system()`, `os.popen()`, `subprocess.run(..., shell=True)` |
| **Path Traversal** | **CWE-22** | A01:2021-Broken Access | `open()`, `send_file()`, `fs.readFile()` without basename validation |
| **Insecure Deserialization** | **CWE-502** | A08:2021-Software Integrity | `pickle.loads()`, `pickle.load()`, `yaml.load()` without SafeLoader |
| **Hardcoded Secrets** | **CWE-798** | A07:2021-Auth Failures | High-entropy strings assigned to `api_key`, `secret`, `jwt_token` |
| **Dynamic Code Evaluation** | **CWE-95** | A03:2021-Injection | `eval()`, `exec()`, `Function()` with dynamic arguments |
| **Insecure Cryptography** | **CWE-327** | A02:2021-Crypto Failures | `hashlib.md5()`, `hashlib.sha1()`, `DES`, `ARC4` |
| **Insecure Temporary File** | **CWE-377** | A01:2021-Broken Access | `tempfile.mktemp()` vulnerable to TOCTOU symlink races |
| **XML External Entity (XXE)** | **CWE-611** | A05:2021-Security Config | `xml.etree.ElementTree.parse()` without entity restriction |
| **DOM-based XSS** | **CWE-79** | A03:2021-Injection | `innerHTML`, `outerHTML`, `document.write` without DOMPurify |
| **Prototype Pollution** | **CWE-1321** | A03:2021-Injection | Unvalidated `__proto__`, `constructor.prototype` object mutation |
| **Server-Side Request Forgery** | **CWE-918** | A10:2021-SSRF | `requests.get()`, `urllib.request.urlopen()` with dynamic targets |

---

## 4. Defense Recognition & Sanitizer Handling

The AST scanner recognizes verified defenses to eliminate false alarms:
1. **Parameterized Queries**: Calls such as `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` where the query string is non-dynamic and arguments are passed in discrete tuple containers are verified as safe.
2. **Type Casting**: Dynamic concatenation containing variables strictly cast to numeric types (e.g. `int(user_id)`) are recognized as safe against SQL injection syntax alterations.
3. **Canonical Path Containment**: File accesses preceded by `os.path.basename()` or `abspath(target).startswith(BASE_DIR)` are recognized as safe against directory climbing (`../`).
4. **Shell Invariant Process Calls**: Subprocess invocations with `shell=False` and structured command arrays are recognized as safe against shell metacharacter injection.

---

## 5. Graceful Error Handling & Language Boundaries

1. **Syntax Errors**: If source code cannot be compiled due to syntax errors (e.g. unclosed parenthesis or invalid keywords), the scanner captures `ast.SyntaxError`, reports line and column offsets, and tags the finding as `SYNTAX_ERROR` (`CWE-1007`) without crashing.
2. **Language Coverage Boundaries**:
   - Python analysis covers all standard Python 3.8–3.14 syntax constructs.
   - JavaScript analysis currently covers ES6+ web frontends and CommonJS/ESM Node.js backend files. Highly dynamic runtime property accesses (e.g. `obj[computedVar1][computedVar2] = val`) are flagged with structural warnings rather than verified flow proofs.
