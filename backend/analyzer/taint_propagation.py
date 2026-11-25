"""
Taint Propagation rules and expression evaluation for SecureCode AI.
Handles propagation across binary expressions, f-strings, method chaining, and sanitizer calls.
"""

import ast
from typing import Dict, List, Optional, Tuple, Set
from .taint_state import TaintStatus, TaintVariable
from .sanitizer_registry import SanitizerRegistry


class TaintPropagator:
    """Evaluates how taint flows through Python AST expressions."""

    @staticmethod
    def get_referenced_names(node: ast.AST) -> List[str]:
        """Collects all variable identifiers read within an expression."""
        names = []
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                names.append(n.id)
        return list(set(names))

    @staticmethod
    def get_call_signature(call_node: ast.Call) -> str:
        """Extracts the full name of a function or method call."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            base = ""
            if isinstance(call_node.func.value, ast.Name):
                base = call_node.func.value.id
            elif isinstance(call_node.func.value, ast.Attribute):
                # e.g. os.path.basename
                attr_parts = []
                curr = call_node.func.value
                while isinstance(curr, ast.Attribute):
                    attr_parts.append(curr.attr)
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    attr_parts.append(curr.id)
                base = ".".join(reversed(attr_parts))
            if base:
                return f"{base}.{call_node.func.attr}"
            return call_node.func.attr
        return ""

    @classmethod
    def evaluate_expression_taint(
        cls,
        node: ast.AST,
        taint_map: Dict[str, TaintVariable],
        target_cwe: str,
    ) -> Tuple[TaintStatus, Optional[str], List[str]]:
        """
        Evaluates the taint status of an AST expression:
        Returns:
            (status: TaintStatus, sanitizer_name: Optional[str], contributing_vars: List[str])
        """
        # 1. Direct variable reference: e.g. x
        if isinstance(node, ast.Name):
            var_name = node.id
            if var_name in taint_map:
                var = taint_map[var_name]
                return var.status, var.sanitizer_name, [var_name]
            return TaintStatus.UNTAINTED, None, []

        # 2. Function or method call: e.g. int(user_input), html.escape(param), func(x)
        if isinstance(node, ast.Call):
            call_sig = cls.get_call_signature(node)
            # Check if this call is a verified sanitizer for target CWE
            if SanitizerRegistry.is_sanitizer(call_sig, target_cwe, language="python"):
                return TaintStatus.SANITIZED, call_sig, cls.get_referenced_names(node)

            # Check if any arguments passed to the call are tainted
            tainted_args: List[str] = []
            for arg in node.args:
                st, san, contributing = cls.evaluate_expression_taint(arg, taint_map, target_cwe)
                if st == TaintStatus.TAINTED:
                    tainted_args.extend(contributing)

            # Check keywords
            for kw in node.keywords:
                st, san, contributing = cls.evaluate_expression_taint(kw.value, taint_map, target_cwe)
                if st == TaintStatus.TAINTED:
                    tainted_args.extend(contributing)

            if tainted_args:
                # If function is string format: e.g. "...".format(tainted)
                return TaintStatus.TAINTED, None, list(set(tainted_args))

            return TaintStatus.UNTAINTED, None, []

        # 3. Binary operations: e.g. "SELECT * FROM t WHERE id=" + user_id
        if isinstance(node, ast.BinOp):
            left_st, left_san, left_vars = cls.evaluate_expression_taint(node.left, taint_map, target_cwe)
            right_st, right_san, right_vars = cls.evaluate_expression_taint(node.right, taint_map, target_cwe)

            # If either side was sanitized specifically for this CWE, that side is safe
            all_vars = list(set(left_vars + right_vars))
            if left_st == TaintStatus.TAINTED or right_st == TaintStatus.TAINTED:
                # If the tainted operand was not sanitized
                return TaintStatus.TAINTED, None, all_vars
            if left_st == TaintStatus.SANITIZED or right_st == TaintStatus.SANITIZED:
                return TaintStatus.SANITIZED, left_san or right_san, all_vars

            return TaintStatus.UNTAINTED, None, []

        # 4. Formatted values and f-strings (JoinedStr): e.g. f"SELECT * FROM t WHERE id={user_id}"
        if isinstance(node, ast.JoinedStr):
            tainted_components: List[str] = []
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    st, san, vars_found = cls.evaluate_expression_taint(val.value, taint_map, target_cwe)
                    if st == TaintStatus.TAINTED:
                        tainted_components.extend(vars_found)
            if tainted_components:
                return TaintStatus.TAINTED, None, list(set(tainted_components))
            return TaintStatus.UNTAINTED, None, []

        # 5. Fallback: check all child names
        ref_names = cls.get_referenced_names(node)
        tainted_refs = [name for name in ref_names if name in taint_map and taint_map[name].status == TaintStatus.TAINTED]
        if tainted_refs:
            return TaintStatus.TAINTED, None, tainted_refs

        return TaintStatus.UNTAINTED, None, []
