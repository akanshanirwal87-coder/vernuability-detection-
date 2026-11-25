import os
from pathlib import Path
from typing import List, Dict, Any, Tuple
from core.config import settings


class RepositoryFileFilter:
    """Filters repository files to exclude non-code, binaries, build outputs, and oversized items."""

    EXCLUDED_DIRS = {
        ".git", ".github", ".gitlab",
        "node_modules", "bower_components",
        "venv", ".venv", "env", ".env",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "dist", "build", "target", "out",
        ".idea", ".vscode",
        ".next", ".nuxt", "coverage", ".tox"
    }

    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".json", ".toml", ".txt"
    }

    BINARY_EXTENSIONS = {
        ".exe", ".dll", ".so", ".dylib", ".bin",
        ".zip", ".tar", ".gz", ".bz2", ".7z",
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pyc", ".pyo", ".class", ".jar", ".war",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".db", ".sqlite", ".sqlite3"
    }

    @classmethod
    def should_scan_file(cls, rel_path: str, size_bytes: int) -> Tuple[bool, str]:
        """Determine if a file should be analyzed, returning (should_scan, reason)."""
        parts = Path(rel_path).parts
        for part in parts[:-1]:
            if part in cls.EXCLUDED_DIRS or part.startswith("."):
                return False, f"Directory '{part}' is excluded"

        ext = Path(rel_path).suffix.lower()

        if ext in cls.BINARY_EXTENSIONS:
            return False, f"Binary or media extension '{ext}' excluded"

        if ext not in cls.SUPPORTED_EXTENSIONS:
            return False, f"Unsupported extension '{ext}'"

        if size_bytes > settings.MAX_REPO_FILE_SIZE_BYTES:
            return False, f"File size ({size_bytes}B) exceeds limit ({settings.MAX_REPO_FILE_SIZE_BYTES}B)"

        return True, "Supported source file"

    @classmethod
    def collect_scannable_files(cls, base_dir: str) -> Dict[str, Any]:
        """Traverse directory and collect eligible files, respecting max file count limit."""
        scannable: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        total_scannable_bytes = 0

        for root, dirs, files in os.walk(base_dir):
            # Prune excluded directories in-place to prevent walking them
            dirs[:] = [d for d in dirs if d not in cls.EXCLUDED_DIRS and not d.startswith(".")]

            for fname in files:
                full_path = os.path.join(root, fname)
                try:
                    rel_path = os.path.relpath(full_path, base_dir)
                    stat = os.stat(full_path)
                    size = stat.st_size

                    eligible, reason = cls.should_scan_file(rel_path, size)
                    if eligible:
                        if len(scannable) >= settings.MAX_REPO_FILES_COUNT:
                            skipped.append({
                                "path": rel_path,
                                "reason": f"Maximum repository file count ({settings.MAX_REPO_FILES_COUNT}) reached"
                            })
                            continue

                        scannable.append({
                            "rel_path": rel_path,
                            "full_path": full_path,
                            "size_bytes": size,
                        })
                        total_scannable_bytes += size
                    else:
                        skipped.append({
                            "path": rel_path,
                            "reason": reason
                        })
                except (OSError, ValueError) as e:
                    skipped.append({
                        "path": fname,
                        "reason": f"Access error: {str(e)}"
                    })

        return {
            "scannable_files": scannable,
            "skipped_files": skipped,
            "total_files_found": len(scannable) + len(skipped),
            "total_scannable_count": len(scannable),
            "total_scannable_bytes": total_scannable_bytes,
        }
