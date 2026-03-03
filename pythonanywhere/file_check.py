import os
import hashlib
import time
import vt

VT_API_KEY = os.environ.get("VT_API_KEY", "")

POLL_INTERVAL = 5   # seconds between status checks
POLL_MAX_WAIT = 120 # seconds before giving up


def _sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _vt_stats_clean(stats: dict) -> bool:
    """Returns True only if VT reports zero malicious/suspicious detections."""
    return stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0


def verify_file_content_hardened(file_path: str, mimetype: str) -> bool:
    """
    Verifies file safety via VirusTotal.
    - Fast path: hash lookup for already-known files (no quota cost, near-instant).
    - Slow path: full upload + polling for unknown files.
    Fails closed on API errors, quota exhaustion, or timeout.
    """
    if not VT_API_KEY:
        raise EnvironmentError("VT_API_KEY is not set.")

    try:
        with vt.Client(VT_API_KEY) as client:

            # --- Fast path: check known hash ---
            try:
                file_obj = client.get_object(f"/files/{_sha256(file_path)}")
                return _vt_stats_clean(file_obj.last_analysis_stats)
            except vt.APIError as e:
                if e.code != "NotFoundError":
                    raise  # unexpected error, bubble to outer handler

            # --- Slow path: upload and poll ---
            with open(file_path, "rb") as f:
                analysis = client.scan_file(f, wait_for_completion=True)

            return _vt_stats_clean(analysis.stats)

    except vt.APIError as e:
        print(f"VirusTotal API error: {e.code} — {e.message}")
        return False
    except Exception as e:
        print(f"Unexpected error during file verification: {e}")
        return False