import os
import io
import shutil
import zipfile
import tempfile
from typing import Optional, Tuple
from integrations.github_client import GitHubClient, GitHubApiError
from core.config import settings
from core.logging_config import logger


class RepositoryDownloaderError(Exception):
    """Raised when repository archive download or extraction fails."""
    pass


class RepositoryDownloader:
    """Securely downloads, extracts, and isolates GitHub repository archives."""

    def __init__(self, client: Optional[GitHubClient] = None):
        self.client = client or GitHubClient()

    def download_and_extract(
        self,
        owner: str,
        repo: str,
        ref: str,
        destination_dir: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Download zipball from GitHub API, stream with size limits, and extract safely.
        Returns: (extracted_root_directory, resolved_commit_sha)
        """
        dest_root = destination_dir or tempfile.mkdtemp(prefix="securecode_repo_")

        try:
            resp = self.client.download_zipball_stream(owner, repo, ref)
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > settings.MAX_REPO_ARCHIVE_SIZE_BYTES:
                raise RepositoryDownloaderError(
                    f"Repository archive size ({content_length} bytes) exceeds maximum allowed ({settings.MAX_REPO_ARCHIVE_SIZE_BYTES} bytes)."
                )

            # Stream download with byte counter to protect against uncompressed/chunked zip bombs
            downloaded_bytes = 0
            buffer = io.BytesIO()

            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > settings.MAX_REPO_ARCHIVE_SIZE_BYTES:
                        raise RepositoryDownloaderError(
                            f"Download exceeded archive size limit of {settings.MAX_REPO_ARCHIVE_SIZE_BYTES} bytes."
                        )
                    buffer.write(chunk)

            buffer.seek(0)

            # Extract zip safely with Zip Slip / Path Traversal prevention
            try:
                with zipfile.ZipFile(buffer) as zf:
                    cls_dir = os.path.realpath(dest_root)

                    # Extract all members verifying canonical containment
                    for member in zf.infolist():
                        # Prevent extraction of symlinks or devices
                        target_path = os.path.realpath(os.path.join(dest_root, member.filename))

                        # Ensure target path starts with dest_root directory
                        if not target_path.startswith(cls_dir + os.sep) and target_path != cls_dir:
                            raise RepositoryDownloaderError(
                                f"Zip Slip detected! Member '{member.filename}' extracts outside destination directory."
                            )

                        zf.extract(member, dest_root)

            except zipfile.BadZipFile as e:
                raise RepositoryDownloaderError(f"Corrupt or invalid zip archive from GitHub: {str(e)}")

            # GitHub zipballs create a single root directory: owner-repo-sha/
            extracted_subdirs = [
                os.path.join(dest_root, d) for d in os.listdir(dest_root)
                if os.path.isdir(os.path.join(dest_root, d))
            ]
            repo_root = extracted_subdirs[0] if len(extracted_subdirs) == 1 else dest_root

            # Attempt to extract commit sha from the GitHub root folder name (owner-repo-7chars)
            commit_sha = ref
            folder_name = os.path.basename(repo_root)
            if "-" in folder_name:
                possible_sha = folder_name.split("-")[-1]
                if len(possible_sha) >= 7 and all(c in "0123456789abcdef" for c in possible_sha):
                    commit_sha = possible_sha

            return repo_root, commit_sha

        except Exception as e:
            # Clean up on failure
            self.cleanup(dest_root)
            if isinstance(e, RepositoryDownloaderError):
                raise
            raise RepositoryDownloaderError(f"Failed to acquire repository content: {str(e)}")

    @staticmethod
    def cleanup(dir_path: str) -> None:
        """Securely remove temporary directory tree."""
        if dir_path and os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
            except Exception as e:
                logger.warning("Failed to remove temporary directory '%s': %s", dir_path, str(e))
