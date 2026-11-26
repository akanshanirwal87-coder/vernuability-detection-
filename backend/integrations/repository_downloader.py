import os
import stat
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
        Download zipball from GitHub API, stream with size & zip-bomb limits, and extract safely.
        Returns: (extracted_root_directory, resolved_commit_sha)
        """
        base_tmp = settings.TEMP_DIR_ROOT or None
        dest_root = destination_dir or tempfile.mkdtemp(prefix="securecode_repo_", dir=base_tmp)
        resp = None

        try:
            resp = self.client.download_zipball_stream(owner, repo, ref)
            content_length = resp.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > settings.MAX_REPO_ARCHIVE_SIZE_BYTES:
                        raise RepositoryDownloaderError(
                            f"Repository archive size ({content_length} bytes) exceeds maximum allowed ({settings.MAX_REPO_ARCHIVE_SIZE_BYTES} bytes)."
                        )
                except ValueError:
                    pass

            # Stream download to a spooled temp file to avoid unbounded RAM growth
            downloaded_bytes = 0
            max_archive = settings.MAX_REPO_ARCHIVE_SIZE_BYTES
            max_uncompressed = settings.MAX_REPO_UNCOMPRESSED_SIZE_BYTES
            max_entries = max(settings.MAX_REPO_FILES_COUNT * 4, 2000)

            with tempfile.SpooledTemporaryFile(max_size=5 * 1024 * 1024) as archive_tmp:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        downloaded_bytes += len(chunk)
                        if downloaded_bytes > max_archive:
                            raise RepositoryDownloaderError(
                                f"Download exceeded archive size limit of {max_archive} bytes."
                            )
                        archive_tmp.write(chunk)

                archive_tmp.seek(0)

                # Extract zip safely with Zip Slip, Symlink, and Zip Bomb prevention
                try:
                    with zipfile.ZipFile(archive_tmp) as zf:
                        cls_dir = os.path.realpath(dest_root)
                        members = zf.infolist()
                        if len(members) > max_entries:
                            raise RepositoryDownloaderError(
                                f"Archive contains {len(members)} entries, exceeding safe limit ({max_entries})."
                            )

                        declared_total = 0
                        actual_total = 0

                        for member in members:
                            # Reject symlinks, FIFOs, character/block devices, sockets
                            unix_mode = member.external_attr >> 16
                            if unix_mode and (
                                stat.S_ISLNK(unix_mode)
                                or stat.S_ISFIFO(unix_mode)
                                or stat.S_ISCHR(unix_mode)
                                or stat.S_ISBLK(unix_mode)
                                or stat.S_ISSOCK(unix_mode)
                            ):
                                raise RepositoryDownloaderError(
                                    f"Unsupported or unsafe file type in archive member '{member.filename}'."
                                )

                            if member.file_size < 0:
                                raise RepositoryDownloaderError(f"Invalid archive member size for '{member.filename}'.")

                            declared_total += member.file_size
                            if declared_total > max_uncompressed:
                                raise RepositoryDownloaderError(
                                    f"Archive uncompressed size exceeds safe limit of {max_uncompressed} bytes."
                                )

                            target_path = os.path.realpath(os.path.join(dest_root, member.filename))
                            if not target_path.startswith(cls_dir + os.sep) and target_path != cls_dir:
                                raise RepositoryDownloaderError(
                                    f"Zip Slip detected! Member '{member.filename}' extracts outside destination directory."
                                )

                            if member.is_dir():
                                os.makedirs(target_path, exist_ok=True)
                                continue

                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            # Stream extract and enforce actual uncompressed byte cap (anti zip-bomb)
                            with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                                while True:
                                    buf = src.read(65536)
                                    if not buf:
                                        break
                                    actual_total += len(buf)
                                    if actual_total > max_uncompressed:
                                        raise RepositoryDownloaderError(
                                            f"Extracted archive content exceeded safe limit of {max_uncompressed} bytes."
                                        )
                                    dst.write(buf)

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
            self.cleanup(dest_root)
            if isinstance(e, RepositoryDownloaderError):
                raise
            raise RepositoryDownloaderError(f"Failed to acquire repository content: {str(e)}")
        finally:
            if resp is not None and hasattr(resp, "close"):
                try:
                    resp.close()
                except Exception:
                    pass

    @staticmethod
    def cleanup(dir_path: str) -> None:
        """Securely remove temporary directory tree."""
        if dir_path and os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
            except Exception as e:
                logger.warning("Failed to remove temporary directory '%s': %s", dir_path, str(e))
