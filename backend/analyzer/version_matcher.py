"""
Version Matcher for SecureCode AI.
Evaluates package versions against OSV.dev advisory affected ranges.
Distinguishes between:
- AFFECTED: Package version falls strictly inside an active vulnerability range or explicit affected versions list.
- UNAFFECTED: Package version is explicitly outside affected ranges or >= a fixed release.
- UNKNOWN: Version is unspecified, unpinned, or cannot be unambiguously evaluated.
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from packaging.version import parse as parse_version, InvalidVersion


class VulnerabilityStatus(str, Enum):
    AFFECTED = "AFFECTED"
    UNAFFECTED = "UNAFFECTED"
    UNKNOWN = "UNKNOWN"


class VersionMatcher:
    """
    Evaluates whether a given package version matches OSV vulnerability range events.
    """

    @staticmethod
    def clean_version_str(ver_str: str) -> str:
        """Strips leading 'v' or 'V' and extra whitespace."""
        s = ver_str.strip()
        if s.startswith("v") or s.startswith("V"):
            s = s[1:]
        return s

    @classmethod
    def compare_versions(cls, v1_str: str, v2_str: str) -> Optional[int]:
        """
        Compares two version strings using packaging.version.
        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2
            None if either version cannot be parsed.
        """
        c1 = cls.clean_version_str(v1_str)
        c2 = cls.clean_version_str(v2_str)
        try:
            pv1 = parse_version(c1)
            pv2 = parse_version(c2)
            if pv1 < pv2:
                return -1
            elif pv1 > pv2:
                return 1
            else:
                return 0
        except InvalidVersion:
            return None

    @classmethod
    def is_version_in_range(
        cls,
        version: str,
        events: List[Dict[str, str]],
    ) -> VulnerabilityStatus:
        """
        Evaluates a version against an ordered sequence of OSV event markers:
        e.g., [{'introduced': '0'}, {'fixed': '1.2.3'}]
        """
        if not version or not events:
            return VulnerabilityStatus.UNKNOWN

        current_introduced: Optional[str] = None
        current_fixed: Optional[str] = None
        current_last_affected: Optional[str] = None

        is_affected = False
        parsed_any_range = False

        for event in events:
            if "introduced" in event:
                current_introduced = event["introduced"]
                current_fixed = None
                current_last_affected = None
            elif "fixed" in event:
                current_fixed = event["fixed"]
            elif "last_affected" in event:
                current_last_affected = event["last_affected"]
            elif "limit" in event:
                current_fixed = event["limit"]

            # If we have an active window, evaluate
            if current_introduced is not None:
                parsed_any_range = True
                cmp_intro = 0 if current_introduced == "0" else cls.compare_versions(version, current_introduced)

                if cmp_intro is not None and cmp_intro >= 0:
                    # Version is at or above introduced
                    # Check fixed upper bound
                    if current_fixed is not None:
                        cmp_fix = cls.compare_versions(version, current_fixed)
                        if cmp_fix is not None:
                            if cmp_fix < 0:
                                is_affected = True
                            else:
                                is_affected = False
                    # Check last_affected upper bound
                    elif current_last_affected is not None:
                        cmp_last = cls.compare_versions(version, current_last_affected)
                        if cmp_last is not None:
                            if cmp_last <= 0:
                                is_affected = True
                            else:
                                is_affected = False
                    else:
                        # Introduced with no upper fixed boundary yet
                        is_affected = True

        if not parsed_any_range:
            return VulnerabilityStatus.UNKNOWN

        return VulnerabilityStatus.AFFECTED if is_affected else VulnerabilityStatus.UNAFFECTED

    @classmethod
    def is_version_affected(
        cls,
        version: str,
        ranges: List[Dict[str, Any]],
        ecosystem: str = "PyPI"
    ) -> Tuple[VulnerabilityStatus, str]:
        """
        Convenience method to evaluate a version against a list of range specifications.
        Returns (VulnerabilityStatus, details_string).
        """
        for r in ranges:
            events = r.get("events", [])
            status = cls.is_version_in_range(version, events)
            if status == VulnerabilityStatus.AFFECTED:
                # Find fixed version if specified
                fixed = next((e["fixed"] for e in events if "fixed" in e), None)
                detail = f"Fixed in {fixed}" if fixed else "No patch version known"
                return status, detail
            elif status == VulnerabilityStatus.UNAFFECTED:
                fixed = next((e["fixed"] for e in events if "fixed" in e), "latest")
                return status, f"Version is patched/unaffected (fixed in {fixed})"

        return VulnerabilityStatus.UNKNOWN, "Could not determine range boundary"

    @classmethod
    def evaluate_advisory(
        cls,
        package_version: Optional[str],
        advisory_data: Dict[str, Any],
        target_package_name: Optional[str] = None,
    ) -> VulnerabilityStatus:
        """
        Evaluates whether package_version is affected by a single OSV advisory JSON object.
        """
        if not package_version or package_version in ("*", "latest"):
            return VulnerabilityStatus.UNKNOWN

        affected_sections = advisory_data.get("affected", [])
        if not affected_sections:
            return VulnerabilityStatus.UNKNOWN

        matched_sections = 0
        overall_status = VulnerabilityStatus.UNAFFECTED

        for aff in affected_sections:
            aff_pkg = aff.get("package", {}).get("name", "").lower()
            if target_package_name and aff_pkg and aff_pkg != target_package_name.lower():
                continue

            matched_sections += 1

            # 1. Explicit versions list in OSV advisory
            explicit_versions = aff.get("versions", [])
            clean_pkg_ver = cls.clean_version_str(package_version)
            cleaned_explicit = [cls.clean_version_str(v) for v in explicit_versions]

            if clean_pkg_ver in cleaned_explicit:
                return VulnerabilityStatus.AFFECTED

            # 2. Ranges evaluation (SEMVER / ECOSYSTEM / GIT)
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                status = cls.is_version_in_range(package_version, events)
                if status == VulnerabilityStatus.AFFECTED:
                    return VulnerabilityStatus.AFFECTED
                elif status == VulnerabilityStatus.UNKNOWN:
                    overall_status = VulnerabilityStatus.UNKNOWN

        if matched_sections == 0:
            return VulnerabilityStatus.UNKNOWN

        return overall_status
