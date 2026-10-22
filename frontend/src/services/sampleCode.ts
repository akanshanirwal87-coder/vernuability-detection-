export interface SampleSnippet {
  id: string;
  name: string;
  language: 'python' | 'javascript';
  category: string;
  description: string;
  vulnerableCode: string;
  secureCode: string;
}

export const SAMPLE_CODE_SNIPPETS: SampleSnippet[] = [
  {
    id: 'sqli-python',
    name: 'SQL Injection in User Query (Python)',
    language: 'python',
    category: 'SQL_INJECTION',
    description: 'Demonstrates raw string concatenation into a database cursor query without parameterization.',
    vulnerableCode: `import sqlite3

def get_user_profile(username: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation creates SQL injection
    # Attacker input like "' OR '1'='1" bypasses authentication
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return user`,
    secureCode: `import sqlite3

def get_user_profile(username: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    
    # SECURE: Use parameterized query with placeholder tuple
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    user = cursor.fetchone()
    conn.close()
    return user`
  },
  {
    id: 'command-injection-python',
    name: 'Command Injection via Ping Utility (Python)',
    language: 'python',
    category: 'COMMAND_INJECTION',
    description: 'Passes unvalidated user input directly into os.system shell execution.',
    vulnerableCode: `import os

def ping_host(target_host: str):
    # VULNERABLE: User input directly concatenated into shell command
    # Payload: "127.0.0.1; cat /etc/passwd" executes arbitrary commands
    command = "ping -c 1 " + target_host
    os.system(command)
    return {"status": "dispatched"}`,
    secureCode: `import subprocess
import ipaddress

def ping_host(target_host: str):
    # SECURE: Validate IP address and execute command as array without shell
    try:
        ipaddress.ip_address(target_host)
    except ValueError:
        raise ValueError("Invalid IP address provided")
        
    result = subprocess.run(
        ["ping", "-c", "1", target_host],
        capture_output=True,
        text=True,
        shell=False,
        check=True
    )
    return {"status": "success", "output": result.stdout}`
  },
  {
    id: 'hardcoded-creds-python',
    name: 'Hardcoded Production Secret (Python)',
    language: 'python',
    category: 'HARDCODED_CREDENTIALS',
    description: 'Hardcoded API token and secret key directly embedded in source repository.',
    vulnerableCode: `import requests

# VULNERABLE: Hardcoded API secret exposed in source control
STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"
DATABASE_URL = "postgres://admin:SuperSecretP@ssw0rd!@10.0.0.4:5432/core_db"

def process_payment(amount: int, customer_id: str):
    headers = {"Authorization": f"Bearer {STRIPE_API_SECRET}"}
    response = requests.post("https://api.stripe.com/v1/charges", headers=headers, json={"amount": amount})
    return response.json()`,
    secureCode: `import os
import requests

# SECURE: Retrieve secrets from environment variables or secrets manager
STRIPE_API_SECRET = os.getenv("STRIPE_API_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

if not STRIPE_API_SECRET:
    raise RuntimeError("Missing required environment variable STRIPE_API_SECRET")

def process_payment(amount: int, customer_id: str):
    headers = {"Authorization": f"Bearer {STRIPE_API_SECRET}"}
    response = requests.post("https://api.stripe.com/v1/charges", headers=headers, json={"amount": amount})
    return response.json()`
  },
  {
    id: 'xss-javascript',
    name: 'Reflected XSS via innerHTML (JavaScript)',
    language: 'javascript',
    category: 'CROSS_SITE_SCRIPTING',
    description: 'Untrusted user query parameter rendered directly using innerHTML without HTML escaping.',
    vulnerableCode: `function displaySearchResults() {
    const urlParams = new URLSearchParams(window.location.search);
    const searchTerm = urlParams.get('q') || '';
    
    const resultsContainer = document.getElementById('search-query-display');
    // VULNERABLE: Direct assignment to innerHTML allows execution of malicious script tags
    // e.g. ?q=<img src=x onerror=alert(document.cookie)>
    resultsContainer.innerHTML = 'Showing results for: <b>' + searchTerm + '</b>';
}`,
    secureCode: `function displaySearchResults() {
    const urlParams = new URLSearchParams(window.location.search);
    const searchTerm = urlParams.get('q') || '';
    
    const resultsContainer = document.getElementById('search-query-display');
    // SECURE: Use textContent or DOM node creation to prevent script execution
    resultsContainer.textContent = 'Showing results for: ';
    const boldTerm = document.createElement('b');
    boldTerm.textContent = searchTerm;
    resultsContainer.appendChild(boldTerm);
}`
  },
  {
    id: 'path-traversal-python',
    name: 'Path Traversal via File Viewer (Python)',
    language: 'python',
    category: 'PATH_TRAVERSAL',
    description: 'Reads files based on user-supplied filename without directory validation, allowing ../ traversal.',
    vulnerableCode: `import os

def read_user_document(filename: str):
    base_dir = "/var/www/uploads/"
    # VULNERABLE: Path concatenation allows ../../etc/passwd traversal
    file_path = base_dir + filename
    
    with open(file_path, "r") as f:
        return f.read()`,
    secureCode: `import os

def read_user_document(filename: str):
    base_dir = os.path.abspath("/var/www/uploads")
    # SECURE: Secure filename resolution and verify target remains inside base_dir
    safe_filename = os.path.basename(filename)
    resolved_path = os.path.abspath(os.path.join(base_dir, safe_filename))
    
    if not resolved_path.startswith(base_dir):
        raise PermissionError("Access outside designated directory forbidden")
        
    with open(resolved_path, "r") as f:
        return f.read()`
  }
];

