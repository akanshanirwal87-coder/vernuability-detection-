"""
Patch Generator for SecureCode AI.
Generates unified diffs and non-destructive patched source code buffers.
Preserves original source code without automatic overwriting.
"""

import difflib
from typing import Dict, Any, Tuple


class PatchGenerator:
    """Creates unified diff patches and simulates source replacement."""

    @classmethod
    def generate_patch(
        cls,
        original_code: str,
        start_line: int,
        end_line: int,
        replacement_snippet: str,
        file_name: str = "source_code.py",
    ) -> Tuple[str, str]:
        """
        Applies a replacement to the specified line range in original_code:
        Returns:
            (patched_code: str, unified_diff: str)
        """
        orig_lines = original_code.splitlines(keepends=True)
        # Handle empty or zero line numbers
        start_idx = max(0, start_line - 1)
        end_idx = min(len(orig_lines), end_line)

        # Prepare replacement lines
        rep_lines = [line + "\n" for line in replacement_snippet.splitlines()]
        if not rep_lines:
            rep_lines = ["\n"]

        # Form new lines array
        new_lines = orig_lines[:start_idx] + rep_lines + orig_lines[end_idx:]
        patched_code = "".join(new_lines)

        # Generate unified diff
        diff_generator = difflib.unified_diff(
            orig_lines,
            new_lines,
            fromfile=f"a/{file_name}",
            tofile=f"b/{file_name}",
            lineterm="",
        )
        diff_str = "\n".join(diff_generator)

        return patched_code, diff_str
