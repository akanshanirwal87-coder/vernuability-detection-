import type { ScanResult, VulnerabilityFinding, ScanHistoryItem } from '../types/scan';

export const DEMO_FINDINGS: VulnerabilityFinding[] = [
  {
    id: 'fnd-sqli-01',
    scanId: 'scan-demo-01',
    title: 'SQL Injection via Unsanitized Query Parameter',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-89',
    owaspCategory: 'A03:2021-Injection',
    file: 'services/auth_service.py',
    startLine: 9,
    endLine: 10,
    confidence: 0.96,
    description: 'User-controlled parameter `username` is directly concatenated into a raw SQL query executed by cursor.execute without using parameter placeholders.',
    evidence: 'query = "SELECT * FROM users WHERE username = \'" + username + "\'"',
    impact: 'An attacker can inject arbitrary SQL statements, allowing authentication bypass, unauthorized data exfiltration, database corruption, or administrative privilege escalation.',
    dataFlow: [
      {
        step: 1,
        label: 'Source: Untrusted Parameter',
        codeSnippet: 'def get_user_profile(username: str):',
        line: 3,
        type: 'SOURCE',
        description: 'Parameter `username` enters the application scope from untrusted client input.'
      },
      {
        step: 2,
        label: 'Transform: Direct String Concatenation',
        codeSnippet: 'query = "SELECT * FROM users WHERE username = \'" + username + "\'"',
        line: 9,
        type: 'TRANSFORM',
        description: 'String concatenation merges untrusted input directly into the executable SQL grammar without encoding.'
      },
      {
        step: 3,
        label: 'Sink: Database Query Execution',
        codeSnippet: 'cursor.execute(query)',
        line: 10,
        type: 'SINK',
        description: 'Vulnerable SQL string passed to database driver execution context.'
      }
    ],
    vulnerableCode: `    # VULNERABLE: Direct string concatenation creates SQL injection
    # Attacker input like "' OR '1'='1" bypasses authentication
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)`,
    remediationCode: `    # SECURE: Use parameterized query with placeholder tuple
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))`,
    remediationExplanation: 'Parameterized queries (prepared statements) ensure the database engine treats input strictly as data values, preventing user input from altering query grammar.',
    bestPractices: [
      'Always use parameter substitution with placeholder tuples (?) or named bindings (:param).',
      'Never concatenate, interpolate, or format strings into SQL statements.',
      'Adopt Object-Relational Mappers (ORMs) such as SQLAlchemy with proper abstraction.'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/89.html',
      'https://owasp.org/Top10/A03_2021-Injection/'
    ],
    remediationStatus: 'OPEN',
    validationStatus: 'NOT_VALIDATED'
  },
  {
    id: 'fnd-cmd-02',
    scanId: 'scan-demo-01',
    title: 'Command Injection in System Utility Dispatcher',
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    owaspCategory: 'A03:2021-Injection',
    file: 'utilities/network_diagnostics.py',
    startLine: 6,
    endLine: 7,
    confidence: 0.98,
    description: 'Untrusted hostname input is passed directly to `os.system()` with shell execution semantics enabled.',
    evidence: 'command = "ping -c 1 " + target_host\nos.system(command)',
    impact: 'Remote code execution (RCE) on the host operating system with the privileges of the running application process.',
    dataFlow: [
      {
        step: 1,
        label: 'Source: Network Target Input',
        codeSnippet: 'def ping_host(target_host: str):',
        line: 3,
        type: 'SOURCE',
        description: 'Client supplied network address parameter.'
      },
      {
        step: 2,
        label: 'Transform: Shell Command Formatting',
        codeSnippet: 'command = "ping -c 1 " + target_host',
        line: 6,
        type: 'TRANSFORM',
        description: 'Direct string concatenation without shell meta-character sanitization.'
      },
      {
        step: 3,
        label: 'Sink: Operating System Shell',
        codeSnippet: 'os.system(command)',
        line: 7,
        type: 'SINK',
        description: 'OS shell interprets operators like ;, &, |, $() to execute arbitrary commands.'
      }
    ],
    vulnerableCode: `    # VULNERABLE: User input directly concatenated into shell command
    command = "ping -c 1 " + target_host
    os.system(command)`,
    remediationCode: `    # SECURE: Use subprocess.run with argument list and shell=False
    try:
        ipaddress.ip_address(target_host)
    except ValueError:
        raise ValueError("Invalid IP address provided")
        
    subprocess.run(["ping", "-c", "1", target_host], shell=False, check=True)`,
    remediationExplanation: 'Use subprocess.run with argument arrays and shell=False to prevent shell interpreters from parsing shell meta-characters.',
    bestPractices: [
      'Disallow direct shell invocation (avoid os.system, os.popen, shell=True).',
      'Validate inputs with strict allowlists (e.g., ipaddress library for IP addresses).',
      'Execute programs using explicit argument vectors.'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/78.html',
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
    ],
    remediationStatus: 'OPEN',
    validationStatus: 'NOT_VALIDATED'
  },
  {
    id: 'fnd-cred-03',
    scanId: 'scan-demo-01',
    title: 'Hardcoded Production API Secret',
    category: 'HARDCODED_CREDENTIALS',
    severity: 'HIGH',
    cwe: 'CWE-798',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    file: 'services/payment_gateway.py',
    startLine: 4,
    endLine: 4,
    confidence: 0.94,
    description: 'High-entropy cryptographic token matching Stripe live secret key pattern detected in plaintext source code.',
    evidence: 'STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"',
    impact: 'Exposed secret permits unauthorized financial transactions, credential theft, and complete billing account takeover.',
    vulnerableCode: `STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"`,
    remediationCode: `STRIPE_API_SECRET = os.getenv("STRIPE_API_SECRET")
if not STRIPE_API_SECRET:
    raise RuntimeError("Missing required environment variable STRIPE_API_SECRET")`,
    remediationExplanation: 'Store all secrets, tokens, and private keys in secure environment variables or dedicated secret management stores (e.g., AWS Secrets Manager, HashiCorp Vault).',
    bestPractices: [
      'Extract credentials into environment variables or secrets managers.',
      'Add credential scanning pre-commit hooks to git repositories.',
      'Immediately rotate and revoke the exposed secret in the provider dashboard.'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    remediationStatus: 'OPEN',
    validationStatus: 'NOT_VALIDATED'
  },
  {
    id: 'fnd-path-04',
    scanId: 'scan-demo-01',
    title: 'Path Traversal via Unvalidated File Path',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    cwe: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    file: 'handlers/document_viewer.py',
    startLine: 6,
    endLine: 8,
    confidence: 0.91,
    description: 'User-specified filename is joined directly with a base directory without verifying whether the canonical path escapes the root directory.',
    evidence: 'file_path = base_dir + filename\nwith open(file_path, "r") as f:',
    impact: 'Arbitrary filesystem read access, allowing retrieval of sensitive system configuration (/etc/passwd), source files, and database credentials.',
    vulnerableCode: `    file_path = base_dir + filename
    with open(file_path, "r") as f:
        return f.read()`,
    remediationCode: `    safe_filename = os.path.basename(filename)
    resolved_path = os.path.abspath(os.path.join(base_dir, safe_filename))
    if not resolved_path.startswith(base_dir):
        raise PermissionError("Access forbidden")
    with open(resolved_path, "r") as f:
        return f.read()`,
    remediationExplanation: 'Extract the basename to prevent path modifiers (../) and verify the resolved absolute path starts with the allowed root directory path.',
    bestPractices: [
      'Use os.path.basename to strip directory traversal sequences.',
      'Canonicalize paths using os.path.realpath and enforce prefix containment.',
      'Restrict filesystem access using sandboxing or dedicated object storage.'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/22.html'
    ],
    remediationStatus: 'OPEN',
    validationStatus: 'NOT_VALIDATED'
  },
  {
    id: 'fnd-crypto-05',
    scanId: 'scan-demo-01',
    title: 'Use of Broken Cryptographic Hash Algorithm (MD5)',
    category: 'INSECURE_CRYPTOGRAPHY',
    severity: 'MEDIUM',
    cwe: 'CWE-327',
    owaspCategory: 'A02:2021-Cryptographic Failures',
    file: 'security/hasher.py',
    startLine: 12,
    endLine: 13,
    confidence: 0.89,
    description: 'Application uses hashlib.md5 for hashing sensitive data. MD5 is cryptographically broken and vulnerable to collision attacks.',
    evidence: 'return hashlib.md5(data.encode()).hexdigest()',
    impact: 'Collision attacks permit forgery of digital signatures, checksums, and token verification.',
    vulnerableCode: `def generate_fingerprint(data: str):
    return hashlib.md5(data.encode()).hexdigest()`,
    remediationCode: `def generate_fingerprint(data: str):
    return hashlib.sha256(data.encode()).hexdigest()`,
    remediationExplanation: 'Upgrade legacy hash algorithms (MD5, SHA1) to modern cryptographic standards like SHA-256 or SHA-512, or bcrypt/Argon2 for passwords.',
    bestPractices: [
      'Never use MD5 or SHA1 for integrity checks or security-sensitive signatures.',
      'Use SHA-256 or SHA-3 for general hashing.',
      'Use Argon2id or bcrypt with high work factor for password hashing.'
    ],
    references: [
      'https://cwe.mitre.org/data/definitions/327.html'
    ],
    remediationStatus: 'OPEN',
    validationStatus: 'NOT_VALIDATED'
  }
];

export const DEMO_SCAN_RESULT: ScanResult = {
  id: 'scan-demo-01',
  projectName: 'PaymentGateway-Core-Service',
  fileName: 'auth_and_payments.py',
  language: 'python',
  createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
  completedAt: new Date(Date.now() - 3600000 * 4 + 4200).toISOString(),
  status: 'COMPLETED',
  durationMs: 4210,
  linesAnalyzed: 482,
  sourceCode: `# PaymentGateway Core Service (Demonstration File)
import sqlite3
import os
import requests
import hashlib

STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"

def get_user_profile(username: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation creates SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def ping_host(target_host: str):
    # VULNERABLE: Command injection via shell concatenation
    command = "ping -c 1 " + target_host
    os.system(command)
    return {"status": "dispatched"}

def read_user_document(filename: str):
    base_dir = "/var/www/uploads/"
    # VULNERABLE: Path traversal
    file_path = base_dir + filename
    with open(file_path, "r") as f:
        return f.read()

def generate_fingerprint(data: str):
    # VULNERABLE: Insecure MD5 hash
    return hashlib.md5(data.encode()).hexdigest()
`,
  highestSeverity: 'CRITICAL',
  findingsCount: {
    critical: 2,
    high: 2,
    medium: 1,
    low: 0,
    total: 5
  },
  findings: DEMO_FINDINGS,
  astSummary: {
    nodesCount: 312,
    functionsFound: 4,
    importsFound: ['sqlite3', 'os', 'requests', 'hashlib'],
    sinksIdentified: 4
  },
  isDemo: true
};

export const DEMO_SCAN_HISTORY: ScanHistoryItem[] = [
  {
    id: 'scan-demo-01',
    projectName: 'PaymentGateway-Core-Service',
    fileName: 'auth_and_payments.py',
    language: 'python',
    createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
    totalFindings: 5,
    highestSeverity: 'CRITICAL',
    status: 'COMPLETED',
    isDemo: true
  },
  {
    id: 'scan-demo-02',
    projectName: 'WebPortal-Frontend-API',
    fileName: 'searchController.js',
    language: 'javascript',
    createdAt: new Date(Date.now() - 3600000 * 26).toISOString(),
    totalFindings: 2,
    highestSeverity: 'HIGH',
    status: 'COMPLETED',
    isDemo: true
  },
  {
    id: 'scan-demo-03',
    projectName: 'SecureAuth-Microservice',
    fileName: 'token_manager.py',
    language: 'python',
    createdAt: new Date(Date.now() - 3600000 * 48).toISOString(),
    totalFindings: 0,
    highestSeverity: 'LOW',
    status: 'COMPLETED',
    isDemo: true
  },
  {
    id: 'scan-demo-04',
    projectName: 'CloudStorage-Sync',
    fileName: 'file_uploader.py',
    language: 'python',
    createdAt: new Date(Date.now() - 3600000 * 72).toISOString(),
    totalFindings: 3,
    highestSeverity: 'HIGH',
    status: 'COMPLETED',
    isDemo: true
  }
];

export const DEMO_DASHBOARD_STATS = {
  totalScans: 28,
  vulnerabilitiesFound: 14,
  criticalFindings: 3,
  remediationProgress: 68, // percentage
  severityDistribution: [
    { name: 'Critical', count: 3, fill: '#EF4444' },
    { name: 'High', count: 5, fill: '#F97316' },
    { name: 'Medium', count: 4, fill: '#F59E0B' },
    { name: 'Low', count: 2, fill: '#10B981' }
  ],
  categoryDistribution: [
    { category: 'SQL Injection', count: 4 },
    { category: 'Command Injection', count: 2 },
    { category: 'Hardcoded Secrets', count: 3 },
    { category: 'Cross-Site Scripting', count: 2 },
    { category: 'Path Traversal', count: 2 },
    { category: 'Insecure Crypto', count: 1 }
  ],
  scanActivityOverTime: [
    { date: 'Mon', scans: 4, findings: 2 },
    { date: 'Tue', scans: 6, findings: 5 },
    { date: 'Wed', scans: 5, findings: 1 },
    { date: 'Thu', scans: 8, findings: 3 },
    { date: 'Fri', scans: 3, findings: 2 },
    { date: 'Sat', scans: 1, findings: 0 },
    { date: 'Sun', scans: 1, findings: 1 }
  ],
  remediationStatusDistribution: [
    { status: 'Remediated & Verified', count: 8, fill: '#10B981' },
    { status: 'Open / Pending Fix', count: 4, fill: '#EF4444' },
    { status: 'Under Review', count: 2, fill: '#F59E0B' }
  ]
};
