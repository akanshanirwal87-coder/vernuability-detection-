"""
Security Feature Extractor for SecureCode AI
Extracts hybrid representation: TF-IDF Code n-grams + Semantic Security Sinks & Guards.
Grounded in OSV.dev CVE advisories and ManageEngine Endpoint Security baselines.
"""

import re
import numpy as np
from typing import List, Dict, Any
from scipy.sparse import hstack, csr_matrix

FEATURE_NAMES = [
    "has_dynamic_interpolation",
    "has_sql_keywords",
    "has_parameterized_query",
    "has_shell_exec_sink",
    "has_safe_process_exec",
    "has_unsafe_deserializer",
    "has_safe_deserializer",
    "has_insecure_crypto",
    "has_secure_crypto",
    "has_dom_xss_sink",
    "has_safe_dom_sink",
    "has_path_traversal_sink",
    "has_path_containment",
    "has_hardcoded_secret",
    "has_env_secret_retrieval",
    "has_osv_package_pattern",
    "has_manageengine_endpoint_rule"
]

def code_tokenizer(text: str) -> List[str]:
    """
    Extracts programming language tokens, function calls, and security symbols.
    """
    tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*|==|!=|\+=|\.|\(|\)|\[|\]|\$|\?|\%s|\+|-|\*|/|`|"|\'', text)
    return [t.lower() for t in tokens if len(t) > 0]

class SecurityFeatureExtractor:
    def __init__(self):
        pass

    @staticmethod
    def extract_structural_features(code: str) -> List[float]:
        c = code.lower()

        # 1. Dynamic string interpolation / concatenation
        dynamic_concat = 1.0 if ('+' in code or 'f"' in code or "f'" in code or '${' in code or '.format(' in code or '% ' in code) else 0.0

        # 2. SQL Query keywords
        sql_kw = 1.0 if any(k in c for k in ['select ', 'insert into', 'update ', 'delete from', 'drop table']) else 0.0

        # 3. Parameterized SQL placeholders
        param_query = 1.0 if ('?' in code or '%s' in code or '$1' in code or ':id' in c or ':email' in c or 'execute(query, (' in c) else 0.0

        # 4. Shell execution sinks
        shell_sink = 1.0 if ('shell=true' in c or 'os.system(' in c or 'child_process.exec(' in c or 'os.popen(' in c or 'subprocess.call(' in c) else 0.0

        # 5. Safe process execution
        safe_proc = 1.0 if ('shell=false' in c or 'subprocess.run([' in c or 'execfile' in c or 'check_output([' in c) else 0.0

        # 6. Unsafe deserialization
        unsafe_deser = 1.0 if ('pickle.loads' in c or 'yaml.load(' in c or 'cpickle' in c or 'marshal.loads' in c or 'node_serialize' in c) else 0.0

        # 7. Safe deserialization
        safe_deser = 1.0 if ('json.loads' in c or 'yaml.safe_load' in c or 'literal_eval' in c or 'json.parse' in c) else 0.0

        # 8. Insecure crypto
        insec_crypto = 1.0 if ('md5(' in c or 'sha1(' in c or 'des.new' in c or 'arc4' in c or 'blowfish' in c) else 0.0

        # 9. Secure crypto
        sec_crypto = 1.0 if ('sha256(' in c or 'sha512(' in c or 'aesgcm' in c or 'bcrypt' in c or 'argon2' in c) else 0.0

        # 10. DOM XSS sink
        dom_xss = 1.0 if ('innerhtml' in c or 'document.write' in c or 'outerhtml' in c or '.html(' in c) else 0.0

        # 11. Safe DOM text
        safe_dom = 1.0 if ('textcontent' in c or 'innertext' in c or '.text(' in c or 'createelement' in c) else 0.0

        # 12. Path traversal sink
        path_sink = 1.0 if (('open(' in c or 'readfilesync' in c or 'send_file' in c or 'createreadstream' in c) and ('basename' not in c and 'abspath' not in c)) else 0.0

        # 13. Path containment guard
        path_guard = 1.0 if ('basename(' in c or 'abspath(' in c or 'resolve(' in c or 'secure_filename' in c or 'startswith(base' in c) else 0.0

        # 14. Hardcoded Secret pattern
        secret_match = 1.0 if re.search(r'(?:api_key|token|secret|password|bearer|auth)\s*=\s*[\'"][^\'"]{8,}[\'"]', code, re.IGNORECASE) else 0.0

        # 15. Environment variable secret retrieval
        env_secret = 1.0 if ('os.getenv' in c or 'os.environ.get' in c or 'process.env' in c) else 0.0

        # 16. OSV vulnerable component pattern
        osv_pattern = 1.0 if any(p in c for p in ['requests.', 'urllib3.', 'lodash.', 'py.path', 'sql-template']) else 0.0

        # 17. ManageEngine endpoint baseline violation
        me_pattern = 1.0 if any(p in c for p in ['agent_payload', 'service_manager.exe', 'endpoint_devices', 'agent_auth_token']) else 0.0

        return [
            dynamic_concat,
            sql_kw,
            param_query,
            shell_sink,
            safe_proc,
            unsafe_deser,
            safe_deser,
            insec_crypto,
            sec_crypto,
            dom_xss,
            safe_dom,
            path_sink,
            path_guard,
            secret_match,
            env_secret,
            osv_pattern,
            me_pattern
        ]

    @staticmethod
    def transform_code(code: str, vectorizer) -> csr_matrix:
        """
        Transforms a code string into combined TF-IDF + Structural feature vector.
        """
        tfidf_feat = vectorizer.transform([code])
        struct_feat = np.array([SecurityFeatureExtractor.extract_structural_features(code)])
        return hstack([tfidf_feat, struct_feat], format='csr')

    @staticmethod
    def transform_corpus(corpus: List[str], vectorizer) -> csr_matrix:
        """
        Transforms a list of code snippets into combined feature matrix.
        """
        tfidf_mat = vectorizer.transform(corpus)
        struct_mat = np.array([SecurityFeatureExtractor.extract_structural_features(c) for c in corpus])
        return hstack([tfidf_mat, struct_mat], format='csr')

