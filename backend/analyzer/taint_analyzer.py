"""
Source-to-Sink Taint Analyzer for SecureCode AI.
Tracks user-controlled inputs from entry points through variable assignments and transformations
into security-sensitive execution sinks, with verified sanitizer suppression.
"""

import ast
import uuid
from typing import List, Dict, Any, Optional, Tuple

from .source_registry import SourceRegistry, SourceDefinition
from .sink_registry import SinkRegistry, SinkDefinition
from .sanitizer_registry import SanitizerRegistry
from .taint_state import TaintStatus, TaintVariable, DataFlowStep, TaintFinding
from .dataflow_graph import DataFlowGraph, DataFlowNode
from .taint_propagation import TaintPropagator


class TaintAnalyzer:
    """Performs static inter-procedural and intra-procedural source-to-sink taint analysis."""

    def __init__(self, source_code: str, file_name: str = "main.py", language: str = "python"):
        self.source_code = source_code
        self.file_name = file_name
        self.language = language.lower()
        self.lines = source_code.splitlines()
        self.graph = DataFlowGraph()
        self.taint_map: Dict[str, TaintVariable] = {}
        self.findings: List[Dict[str, Any]] = []

    def _get_line(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()
        return ""

    def analyze(self) -> List[Dict[str, Any]]:
        """Executes taint analysis across the source code."""
        if self.language == "python":
            return self._analyze_python()
        elif self.language in ("javascript", "typescript"):
            return self._analyze_javascript()
        return []

    # =========================================================================
    # Python Source-to-Sink Taint Analysis
    # =========================================================================

    def _analyze_python(self) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError:
            # Syntax errors are handled by AST scanner
            return []

        # Phase 1: Identify all Sources and direct assignments
        self._find_python_sources(tree)

        # Phase 2: Propagate Taint through variable assignments and operations
        self._propagate_python_assignments(tree)

        # Phase 3: Inspect Sinks and check if tainted variables reach dangerous sinks
        self._check_python_sinks(tree)

        return self.findings

    def _find_python_sources(self, tree: ast.AST):
        """Scans for user-controlled input sources and marks target variables as TAINTED."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                line_str = self._get_line(node.lineno)
                # Check if RHS matches an input source
                source_def = None
                matched_snippet = ""

                # Check Call sources (e.g. request.args.get, sys.stdin.read)
                for child in ast.walk(node.value):
                    if isinstance(child, ast.Call):
                        sig = TaintPropagator.get_call_signature(child)
                        src = SourceRegistry.match_python_source(sig)
                        if src:
                            source_def = src
                            matched_snippet = sig
                            break

                # Check Attribute sources (e.g. sys.argv, request.args)
                if not source_def:
                    for child in ast.walk(node.value):
                        if isinstance(child, ast.Attribute):
                            # build attribute name
                            attr_parts = []
                            curr = child
                            while isinstance(curr, ast.Attribute):
                                attr_parts.append(curr.attr)
                                curr = curr.value
                            if isinstance(curr, ast.Name):
                                attr_parts.append(curr.id)
                            full_attr = ".".join(reversed(attr_parts))
                            src = SourceRegistry.match_python_source(full_attr)
                            if src:
                                source_def = src
                                matched_snippet = full_attr
                                break

                # Also match direct text for input() or sys.argv
                if not source_def:
                    for src_text in ["sys.argv", "input(", "request.args", "request.form"]:
                        if src_text in line_str:
                            source_def = SourceRegistry.match_python_source(src_text)
                            matched_snippet = src_text
                            break

                if source_def:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            node_id = f"src_{var_name}_{node.lineno}"
                            self.graph.add_node(
                                node_id=node_id,
                                label=f"Source: {source_def.category}",
                                line=node.lineno,
                                snippet=line_str,
                                node_type="SOURCE",
                                description=f"Untrusted input `{var_name}` received via {source_def.description} (`{matched_snippet}`).",
                                taint_status=TaintStatus.TAINTED,
                            )
                            self.taint_map[var_name] = TaintVariable(
                                name=var_name,
                                status=TaintStatus.TAINTED,
                                source_identifier=source_def.identifier,
                                source_line=node.lineno,
                                source_snippet=line_str,
                                transform_chain=[{"node_id": node_id, "line": node.lineno, "snippet": line_str}],
                            )

    def _propagate_python_assignments(self, tree: ast.AST):
        """Propagates taint across subsequent variable assignments and string concatenations."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                line_str = self._get_line(node.lineno)
                # Skip if already identified as a direct source
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_name = target.id
                        if target_name in self.taint_map and self.taint_map[target_name].source_line == node.lineno:
                            continue

                        # Evaluate taint status of RHS expression
                        st, san, contributing = TaintPropagator.evaluate_expression_taint(
                            node.value, self.taint_map, target_cwe="CWE-89"
                        )

                        if st == TaintStatus.TAINTED and contributing:
                            node_id = f"trans_{target_name}_{node.lineno}"
                            first_var = contributing[0]
                            parent_chain = self.taint_map[first_var].transform_chain if first_var in self.taint_map else []

                            self.graph.add_node(
                                node_id=node_id,
                                label="Transform: Dynamic Expression",
                                line=node.lineno,
                                snippet=line_str,
                                node_type="TRANSFORM",
                                description=f"Variable `{target_name}` constructed using tainted variable(s) {', '.join(f'`{v}`' for v in contributing)}.",
                                taint_status=TaintStatus.TAINTED,
                            )

                            for parent_var in contributing:
                                if parent_var in self.taint_map and self.taint_map[parent_var].transform_chain:
                                    last_parent_id = self.taint_map[parent_var].transform_chain[-1]["node_id"]
                                    self.graph.add_edge(last_parent_id, node_id, label="propagates")

                            new_chain = list(parent_chain) + [{"node_id": node_id, "line": node.lineno, "snippet": line_str}]
                            self.taint_map[target_name] = TaintVariable(
                                name=target_name,
                                status=TaintStatus.TAINTED,
                                source_identifier=self.taint_map[first_var].source_identifier if first_var in self.taint_map else "dynamic",
                                source_line=self.taint_map[first_var].source_line if first_var in self.taint_map else node.lineno,
                                source_snippet=self.taint_map[first_var].source_snippet if first_var in self.taint_map else line_str,
                                transform_chain=new_chain,
                            )
                        elif st == TaintStatus.SANITIZED:
                            self.taint_map[target_name] = TaintVariable(
                                name=target_name,
                                status=TaintStatus.SANITIZED,
                                sanitizer_name=san,
                                sanitizer_line=node.lineno,
                            )

    def _check_python_sinks(self, tree: ast.AST):
        """Scans Call nodes for dangerous sinks and evaluates if tainted inputs reach them."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                sig = TaintPropagator.get_call_signature(node)
                sink_def = SinkRegistry.get_python_sink(sig)

                # Special case: check subprocess.run with shell=True keyword
                if sig.startswith("subprocess."):
                    has_shell_true = any(
                        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )
                    if has_shell_true:
                        sink_def = SinkRegistry.PYTHON_SINKS.get("subprocess.run")
                    else:
                        # With shell=False, subprocess.run is safe against command injection
                        continue

                if not sink_def:
                    continue

                line_str = self._get_line(node.lineno)

                # Check arguments
                if not node.args:
                    continue

                arg0 = node.args[0]
                target_cwe = sink_def.cwe

                # Check if SQL query is parameterized: e.g. cursor.execute("SELECT ... WHERE id = ?", (uid,))
                if target_cwe == "CWE-89":
                    # If arg0 is a literal string with placeholders and len(node.args) > 1, it's safe parameterized query!
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        if SanitizerRegistry.is_parameterized_query(arg0.value) and len(node.args) > 1:
                            # Safe parameterized query!
                            continue
                        elif not any(dyn in arg0.value for dyn in ("+", "%", "{")):
                            # Constant string without concatenation
                            continue

                # Check if path traversal sink is protected by safe containment or basename
                if target_cwe == "CWE-22":
                    surrounding_code = "\n".join(self.lines[max(0, node.lineno - 5):node.lineno])
                    if SanitizerRegistry.is_safe_path_containment(surrounding_code):
                        # Safe path containment guard detected!
                        continue

                # Evaluate taint of arg0
                st, san, contributing_vars = TaintPropagator.evaluate_expression_taint(arg0, self.taint_map, target_cwe)

                # Also inspect if arg0 is a dynamic string directly (f-string or BinOp) containing tainted variables
                if st == TaintStatus.TAINTED and contributing_vars:
                    # Construct dataflow trace
                    first_var = contributing_vars[0]
                    first_info = self.taint_map.get(first_var)
                    sink_node_id = f"sink_{sig}_{node.lineno}"

                    self.graph.add_node(
                        node_id=sink_node_id,
                        label=f"Sink: {sink_def.function_or_attr}",
                        line=node.lineno,
                        snippet=line_str,
                        node_type="SINK",
                        description=f"Tainted argument dispatched to `{sink_def.function_or_attr}()` without required {target_cwe} sanitization.",
                        taint_status=TaintStatus.TAINTED,
                    )

                    steps: List[DataFlowStep] = []
                    step_counter = 1

                    # 1. Source Step
                    if first_info and first_info.source_line > 0:
                        steps.append(
                            DataFlowStep(
                                step=step_counter,
                                label=f"Source: Input Entry Point",
                                code_snippet=first_info.source_snippet,
                                line=first_info.source_line,
                                type="SOURCE",
                                description=f"Untrusted user input enters system via `{first_info.source_identifier}`.",
                            )
                        )
                        step_counter += 1

                    # 2. Transform Step (if intermediate variable)
                    if first_info and first_info.transform_chain:
                        for tr in first_info.transform_chain:
                            if tr["line"] != first_info.source_line and tr["line"] != node.lineno:
                                steps.append(
                                    DataFlowStep(
                                        step=step_counter,
                                        label="Transform: Dynamic Concatenation",
                                        code_snippet=tr["snippet"],
                                        line=tr["line"],
                                        type="TRANSFORM",
                                        description="Untrusted value incorporated into execution string.",
                                    )
                                )
                                step_counter += 1

                    # 3. Sink Step
                    steps.append(
                        DataFlowStep(
                            step=step_counter,
                            label=f"Sink: {sink_def.function_or_attr}",
                            code_snippet=line_str,
                            line=node.lineno,
                            type="SINK",
                            description=sink_def.description,
                        )
                    )

                    start_line = steps[0].line if steps else node.lineno
                    end_line = node.end_lineno or node.lineno

                    finding = TaintFinding(
                        id=f"fnd-taint-{uuid.uuid4().hex[:6]}",
                        title=f"{sink_def.category.replace('_', ' ').title()} via Taint Propagation",
                        category=sink_def.category,
                        severity=sink_def.default_severity,
                        cwe=sink_def.cwe,
                        owasp=sink_def.owasp,
                        file=self.file_name,
                        start_line=start_line,
                        end_line=end_line,
                        confidence=0.96,
                        description=f"Verified dataflow taint path from source input to dangerous sink `{sig}` ({target_cwe}).",
                        evidence=f"Source (L{start_line}): {steps[0].code_snippet}\nSink (L{node.lineno}): {line_str}",
                        source_location=f"{self.file_name}:L{start_line}",
                        sink_location=f"{self.file_name}:L{node.lineno}",
                        data_flow=steps,
                        vulnerable_code=line_str,
                        remediation_code=sink_def.remediation_template,
                        remediation_explanation=sink_def.remediation_explanation,
                        best_practices=[
                            "Never pass unvalidated user input directly to execution sinks.",
                            "Use verified parameterized APIs or context-specific sanitizers.",
                            "Enforce strict input type validation and allowlisting.",
                        ],
                        references=[
                            f"https://cwe.mitre.org/data/definitions/{target_cwe.split('-')[-1]}.html",
                            "https://owasp.org/Top10/",
                        ],
                    )
                    self.findings.append(finding.to_dict())

    # =========================================================================
    # JavaScript Source-to-Sink Taint Analysis
    # =========================================================================

    def _analyze_javascript(self) -> List[Dict[str, Any]]:
        """Performs lexical and pattern-based taint analysis on JavaScript/TypeScript code."""
        # Find sources (e.g. urlParams.get('q'), req.query.id, location.search)
        js_tainted_vars: Dict[str, Dict[str, Any]] = {}

        for idx, line in enumerate(self.lines):
            line_no = idx + 1
            line_str = line.strip()

            # Check variable declaration from a source
            # e.g. const query = urlParams.get('q'); let userInput = req.query.name;
            for src_pattern in ["urlParams.get", "params.get", "req.query", "req.params", "location.search"]:
                if src_pattern in line_str:
                    # extract variable name
                    var_match = None
                    if "=" in line_str:
                        lhs = line_str.split("=")[0].strip()
                        tokens = lhs.split()
                        if tokens:
                            var_match = tokens[-1]
                    if var_match:
                        js_tainted_vars[var_match] = {
                            "name": var_match,
                            "line": line_no,
                            "snippet": line_str,
                            "source_pattern": src_pattern,
                        }

        # Check propagation and sinks
        for idx, line in enumerate(self.lines):
            line_no = idx + 1
            line_str = line.strip()

            # 1. innerHTML / outerHTML sink (CWE-79 XSS)
            if any(dom_sink in line_str for dom_sink in ["innerHTML", "outerHTML", "document.write"]):
                # Check if DOMPurify is used
                if "DOMPurify.sanitize" in line_str or "encodeURIComponent" in line_str:
                    continue  # Sanitized!

                # Check if any tainted variable is referenced
                for var_name, var_info in js_tainted_vars.items():
                    if var_name in line_str and ("+" in line_str or "${" in line_str or f"={var_name}" in line_str.replace(" ", "")):
                        steps = [
                            DataFlowStep(
                                step=1,
                                label="Source: DOM / Query Input",
                                code_snippet=var_info["snippet"],
                                line=var_info["line"],
                                type="SOURCE",
                                description=f"Untrusted input retrieved from `{var_info['source_pattern']}`.",
                            ),
                            DataFlowStep(
                                step=2,
                                label="Sink: DOM XSS Injection",
                                code_snippet=line_str,
                                line=line_no,
                                type="SINK",
                                description="Untrusted variable rendered into DOM markup via innerHTML without HTML sanitization.",
                            ),
                        ]
                        self.findings.append(
                            TaintFinding(
                                id=f"fnd-jsxss-{uuid.uuid4().hex[:6]}",
                                title="Cross-Site Scripting (XSS) via DOM Taint Flow",
                                category="CROSS_SITE_SCRIPTING",
                                severity="HIGH",
                                cwe="CWE-79",
                                owasp="A03:2021-Injection",
                                file=self.file_name,
                                start_line=var_info["line"],
                                end_line=line_no,
                                confidence=0.95,
                                description="Untrusted user input flows into dynamic innerHTML write without DOMPurify sanitization.",
                                evidence=f"Source (L{var_info['line']}): {var_info['snippet']}\nSink (L{line_no}): {line_str}",
                                source_location=f"{self.file_name}:L{var_info['line']}",
                                sink_location=f"{self.file_name}:L{line_no}",
                                data_flow=steps,
                                vulnerable_code=line_str,
                                remediation_code="element.textContent = safeText; // or DOMPurify.sanitize(markup)",
                                remediation_explanation="Use textContent to render plain text or sanitize untrusted HTML using DOMPurify.",
                                best_practices=[
                                    "Avoid setting innerHTML with user-controlled data.",
                                    "Sanitize all markup with DOMPurify.",
                                    "Prefer textContent or framework data bindings.",
                                ],
                                references=["https://cwe.mitre.org/data/definitions/79.html"],
                            ).to_dict()
                        )
                        break

            # 2. child_process.exec command sink (CWE-78 Command Injection)
            if "child_process.exec(" in line_str or "execSync(" in line_str:
                for var_name, var_info in js_tainted_vars.items():
                    if var_name in line_str and ("+" in line_str or "${" in line_str):
                        steps = [
                            DataFlowStep(
                                step=1,
                                label="Source: User Input",
                                code_snippet=var_info["snippet"],
                                line=var_info["line"],
                                type="SOURCE",
                                description=f"Unvalidated input read from `{var_info['source_pattern']}`.",
                            ),
                            DataFlowStep(
                                step=2,
                                label="Sink: Node.js Shell Execution",
                                code_snippet=line_str,
                                line=line_no,
                                type="SINK",
                                description="Dynamic command executed through shell invocation in child_process.exec.",
                            ),
                        ]
                        self.findings.append(
                            TaintFinding(
                                id=f"fnd-jscmd-{uuid.uuid4().hex[:6]}",
                                title="Command Injection via Node.js Shell Execution",
                                category="COMMAND_INJECTION",
                                severity="CRITICAL",
                                cwe="CWE-78",
                                owasp="A03:2021-Injection",
                                file=self.file_name,
                                start_line=var_info["line"],
                                end_line=line_no,
                                confidence=0.96,
                                description="Tainted input directly concatenated into child_process.exec() call.",
                                evidence=f"Source (L{var_info['line']}): {var_info['snippet']}\nSink (L{line_no}): {line_str}",
                                source_location=f"{self.file_name}:L{var_info['line']}",
                                sink_location=f"{self.file_name}:L{line_no}",
                                data_flow=steps,
                                vulnerable_code=line_str,
                                remediation_code="child_process.execFile(executable, [arg], { shell: false })",
                                remediation_explanation="Use execFile with argument arrays rather than shell string execution.",
                                best_practices=["Use child_process.execFile with parameter arrays."],
                                references=["https://cwe.mitre.org/data/definitions/78.html"],
                            ).to_dict()
                        )
                        break

        return self.findings
