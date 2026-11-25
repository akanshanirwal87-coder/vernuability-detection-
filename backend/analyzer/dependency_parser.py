"""
Dependency Manifest Parser for SecureCode AI.
Parses open-source project manifests:
- requirements.txt (Python / PyPI)
- pyproject.toml (PEP 621 & Poetry)
- package.json (Node.js / npm)
- package-lock.json (Node.js / npm resolved lockfile)

Extracts exact resolved versions where available, preserving specifiers and ecosystems.
"""

import os
import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class DependencyItem:
    name: str
    ecosystem: str  # 'PyPI' | 'npm'
    version: Optional[str] = None  # Exact resolved version e.g. '2.31.0'
    version_constraint: Optional[str] = None  # e.g. '>=2.31.0', '^1.2.0'
    is_pinned: bool = False
    source_manifest: str = ""
    is_dev: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Backward-compatible alias
ParsedDependency = DependencyItem


class DependencyParser:
    """
    Parses manifest files and raw content strings into normalized DependencyItem lists.
    """

    @staticmethod
    def is_manifest_file(file_name: str) -> bool:
        """Determines if a filename represents a supported dependency manifest."""
        base = os.path.basename(file_name.lower().replace("\\", "/"))
        return base in (
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "package-lock.json"
        ) or base.endswith(".requirements.txt") or base.endswith("requirements-dev.txt")

    @staticmethod
    def parse_requirements_txt(content: str, manifest_name: str = "requirements.txt") -> List[DependencyItem]:
        """
        Parses requirements.txt content handling comments, options, specifiers, and environment markers.
        """
        items: List[DependencyItem] = []
        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines and full-line comments or flags
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
                continue

            # Strip inline comments
            line = re.split(r'\s+#', line)[0].strip()

            # Strip environment markers (e.g., ; sys_platform == 'win32')
            line = line.split(";")[0].strip()
            if not line:
                continue

            # Check for exact pinning (==)
            exact_match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.\+]+)', line)
            if exact_match:
                pkg_name = exact_match.group(1).lower().replace("_", "-")
                version = exact_match.group(2).strip()
                items.append(DependencyItem(
                    name=pkg_name,
                    ecosystem="PyPI",
                    version=version,
                    version_constraint=f"=={version}",
                    is_pinned=True,
                    source_manifest=manifest_name,
                    is_dev=False
                ))
                continue

            # Check for range specifiers (~=, >=, <=, !=, <, >)
            range_match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([~><!=].*)', line)
            if range_match:
                pkg_name = range_match.group(1).lower().replace("_", "-")
                constraint = range_match.group(2).strip()
                items.append(DependencyItem(
                    name=pkg_name,
                    ecosystem="PyPI",
                    version=None,
                    version_constraint=constraint,
                    is_pinned=False,
                    source_manifest=manifest_name,
                    is_dev=False
                ))
                continue

            # Bare package name without constraints
            bare_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
            if bare_match:
                pkg_name = bare_match.group(1).lower().replace("_", "-")
                items.append(DependencyItem(
                    name=pkg_name,
                    ecosystem="PyPI",
                    version=None,
                    version_constraint="*",
                    is_pinned=False,
                    source_manifest=manifest_name,
                    is_dev=False
                ))

        return items

    @staticmethod
    def parse_pyproject_toml(content: str, manifest_name: str = "pyproject.toml") -> List[DependencyItem]:
        """
        Parses pyproject.toml content (PEP 621 and Poetry dependencies) without external toml library dependency.
        """
        items: List[DependencyItem] = []

        # 1. Parse PEP 621 dependencies array: dependencies = [ "requests>=2.0", "fastapi==0.110.0" ]
        pep621_section = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if pep621_section:
            array_content = pep621_section.group(1)
            entries = re.findall(r'["\']([^"\']+)["\']', array_content)
            for entry in entries:
                parsed = DependencyParser.parse_requirements_txt(entry, manifest_name=manifest_name)
                items.extend(parsed)

        # 2. Parse Poetry dependencies section: [tool.poetry.dependencies]
        poetry_section = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?=\n\[|\Z)', content, re.DOTALL)
        if poetry_section:
            section_text = poetry_section.group(1)
            for line in section_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Match: package_name = "1.2.3" or package_name = "^1.2" or package_name = { version = "1.2.3" }
                m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*=\s*(.*)', line)
                if m:
                    pkg_name = m.group(1).lower().replace("_", "-")
                    if pkg_name == "python":
                        continue  # Skip python interpreter constraint

                    val = m.group(2).strip()
                    # If dictionary: { version = "1.2.3", ... }
                    v_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
                    if v_match:
                        raw_ver = v_match.group(1).strip()
                    else:
                        str_match = re.search(r'["\']([^"\']+)["\']', val)
                        raw_ver = str_match.group(1).strip() if str_match else val

                    is_pinned = bool(re.match(r'^[0-9]+(\.[0-9]+)*$', raw_ver))
                    items.append(DependencyItem(
                        name=pkg_name,
                        ecosystem="PyPI",
                        version=raw_ver if is_pinned else None,
                        version_constraint=f"=={raw_ver}" if is_pinned else raw_ver,
                        is_pinned=is_pinned,
                        source_manifest=manifest_name,
                        is_dev=False
                    ))

        return items

    @staticmethod
    def parse_package_json(content: str, manifest_name: str = "package.json") -> List[DependencyItem]:
        """
        Parses package.json dependencies and devDependencies.
        """
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return items

        dep_sections = [
            ("dependencies", False),
            ("devDependencies", True),
            ("peerDependencies", False),
            ("optionalDependencies", False)
        ]

        for sec, is_dev in dep_sections:
            sec_dict = data.get(sec, {})
            if isinstance(sec_dict, dict):
                for pkg_name, spec in sec_dict.items():
                    if not isinstance(spec, str):
                        continue
                    spec = spec.strip()
                    # Check exact pinning: "1.2.3" without ^, ~, >=, <=, *
                    is_pinned = bool(re.match(r'^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9_\-\.]+)?$', spec))
                    clean_name = pkg_name.strip().lower()
                    items.append(DependencyItem(
                        name=clean_name,
                        ecosystem="npm",
                        version=spec if is_pinned else None,
                        version_constraint=spec,
                        is_pinned=is_pinned,
                        source_manifest=manifest_name,
                        is_dev=is_dev
                    ))

        return items

    @staticmethod
    def parse_package_lock_json(content: str, manifest_name: str = "package-lock.json") -> List[DependencyItem]:
        """
        Parses package-lock.json (supporting lockfileVersion 1, 2, and 3) to extract resolved exact versions.
        """
        items: List[DependencyItem] = []
        try:
            data = json.loads(content)
        except Exception:
            return items

        # lockfileVersion 2/3: "packages" object
        packages = data.get("packages", {})
        if isinstance(packages, dict) and packages:
            for pkg_path, details in packages.items():
                if not pkg_path or pkg_path == "":
                    continue  # Root project package
                if not isinstance(details, dict):
                    continue

                version = details.get("version")
                if not version:
                    continue

                # pkg_path is usually "node_modules/lodash" or "node_modules/@scope/pkg"
                parts = pkg_path.split("node_modules/")
                pkg_name = parts[-1] if len(parts) > 1 else pkg_path
                is_dev = details.get("dev", False)

                items.append(DependencyItem(
                    name=pkg_name.lower(),
                    ecosystem="npm",
                    version=version,
                    version_constraint=f"=={version}",
                    is_pinned=True,
                    source_manifest=manifest_name,
                    is_dev=is_dev
                ))

        # lockfileVersion 1: "dependencies" object
        deps = data.get("dependencies", {})
        if isinstance(deps, dict) and not items:
            for pkg_name, details in deps.items():
                if not isinstance(details, dict):
                    continue
                version = details.get("version")
                if version:
                    items.append(DependencyItem(
                        name=pkg_name.lower(),
                        ecosystem="npm",
                        version=version,
                        version_constraint=f"=={version}",
                        is_pinned=True,
                        source_manifest=manifest_name,
                        is_dev=details.get("dev", False)
                    ))

        return items

    @classmethod
    def parse_manifest(cls, filename: str, content: str) -> List[DependencyItem]:
        """
        Dispatches content to the appropriate parser based on manifest filename.
        """
        basename = os.path.basename(filename).lower()
        if "package-lock.json" in basename:
            return cls.parse_package_lock_json(content, manifest_name=filename)
        elif "package.json" in basename:
            return cls.parse_package_json(content, manifest_name=filename)
        elif "pyproject.toml" in basename:
            return cls.parse_pyproject_toml(content, manifest_name=filename)
        elif "requirements" in basename or basename.endswith(".txt"):
            return cls.parse_requirements_txt(content, manifest_name=filename)
        return []
