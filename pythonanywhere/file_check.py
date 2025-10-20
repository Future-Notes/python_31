import io
import os
import subprocess
import tempfile
from typing import Optional
from multiprocessing import Process, Queue
from PIL import Image, ImageFile

# Optional libs
try:
    import magic  # python-magic (libmagic)
except Exception:
    magic = None

try:
    from pypdf import PdfReader  # or from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

import zipfile

# Configuration limits (tune to your environment)
MAX_PIXELS = 50_000_000        # e.g. 50M pixels total
MAX_WIDTH = 10000
MAX_HEIGHT = 10000
MAX_METADATA_BYTES = 1_000_000  # 1 MB
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED = 1_000_000_000  # 1 GB total uncompressed (tune)
WORKER_TIMEOUT = 8  # seconds for deep checks

# allowed formats mapping
FORMAT_TO_MIME = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "WEBP": "image/webp",
    "ICO" : "image/ico",
    "BMP" : "image/bmp",
}

def _magic_mime(file_path: str) -> Optional[str]:
    if magic is None:
        return None
    try:
        m = magic.Magic(mime=True)
        return m.from_file(file_path)
    except Exception:
        return None

def _safe_read_head(path: str, n: int = 4096) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)

def _image_deep_check(file_path: str, declared_mime: str, q: Queue):
    """
    Runs inside a subprocess/worker to enforce timeouts and memory isolation.
    Puts boolean result in queue.
    """
    try:
        # First, check magic if available
        magic_mime = _magic_mime(file_path)
        if magic_mime and not magic_mime.startswith("image/"):
            q.put(False); return

        # Pillow: verify + full load + checks
        # Allow truncated images to be processed safely by increasing parser tolerances
        ImageFile.LOAD_TRUNCATED_IMAGES = False

        with Image.open(file_path) as img:
            # quick format-to-mime check
            detected_mime = FORMAT_TO_MIME.get(img.format)
            if detected_mime is None or detected_mime != declared_mime:
                q.put(False); return

            # verify file (lightweight)
            try:
                img.verify()
            except Exception:
                q.put(False); return

        # reopen and fully decode
        with Image.open(file_path) as img:
            try:
                img.load()  # forces full decode; catches many issues
            except Exception:
                q.put(False); return

            # resource limits
            if img.width > MAX_WIDTH or img.height > MAX_HEIGHT:
                q.put(False); return
            if img.width * img.height > MAX_PIXELS:
                q.put(False); return

            # optional: check metadata size (exif)
            info = getattr(img, "info", {})
            total_meta_bytes = 0
            for v in info.values():
                try:
                    if isinstance(v, (bytes, bytearray)):
                        total_meta_bytes += len(v)
                    elif isinstance(v, str):
                        total_meta_bytes += len(v.encode("utf-8", errors="ignore"))
                except Exception:
                    pass
            if total_meta_bytes > MAX_METADATA_BYTES:
                q.put(False); return

            # attempt re-encode into an in-memory buffer using declared format
            buf = io.BytesIO()
            try:
                save_format = img.format  # keep original format
                img.save(buf, format=save_format)
            except Exception:
                q.put(False); return

        q.put(True)
    except Exception:
        q.put(False)

def _pdf_deep_check(file_path: str, q: Queue):
    try:
        # basic header/trailer
        with open(file_path, "rb") as f:
            head = f.read(5)
            if not head.startswith(b"%PDF"):
                q.put(False); return
            f.seek(-1024, os.SEEK_END)
            tail = f.read().strip()
            if b"%%EOF" not in tail:
                # could be still valid (linearized, or extra bytes) but be conservative
                q.put(False); return

        # use PyPDF to try reading basic structure
        if PdfReader is None:
            q.put(False); return

        try:
            reader = PdfReader(file_path)
            # minimal sanity: at least 1 page and a /Root entry
            if len(reader.pages) < 1:
                q.put(False); return
            trailer = getattr(reader, "trailer", {})
            if "/Root" not in trailer:
                # Some readers may expose different structs; be conservative
                q.put(False); return
        except Exception:
            q.put(False); return

        q.put(True)
    except Exception:
        q.put(False)

def _zip_deep_check(file_path: str, q: Queue):
    try:
        # header check
        with open(file_path, "rb") as f:
            sig = f.read(4)
            if sig != b"PK\x03\x04":
                q.put(False); return

        # Use zipfile to inspect entries but do NOT extract
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
                if len(namelist) == 0:
                    q.put(False); return
                if len(namelist) > MAX_ZIP_ENTRIES:
                    q.put(False); return

                total_uncompressed = 0
                seen_names = set()
                for zi in zf.infolist():
                    # Path traversal check
                    if zi.filename.startswith("/") or ".." in zi.filename.replace("\\", "/").split("/"):
                        q.put(False); return

                    # overlapping or suspicious compressed size ratio check
                    total_uncompressed += zi.file_size
                    if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
                        q.put(False); return

                    # optional: check for duplicate names
                    if zi.filename in seen_names:
                        # suspicious duplicate
                        q.put(False); return
                    seen_names.add(zi.filename)

                # testzip checks CRCs; returns name of bad file or None
                if zf.testzip() is not None:
                    q.put(False); return

                # optionally detect "overlap" malicious entries by reading central directory flags
                # newer Python versions patched many issues; rely on stdlib checks + limits
        except zipfile.BadZipFile:
            q.put(False); return

        q.put(True)
    except Exception:
        q.put(False)

def run_with_timeout(fn, args=(), timeout=WORKER_TIMEOUT) -> bool:
    q = Queue(1)
    p = Process(target=fn, args=(*args, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return False
    try:
        return bool(q.get_nowait())
    except Exception:
        return False

# MAIN verifier
def verify_file_content_hardened(file_path: str, mimetype: str) -> bool:
    # quick magic check first if available
    magic_mime = _magic_mime(file_path)
    if magic_mime and mimetype and not magic_mime.startswith(mimetype.split("/")[0]):
        # e.g. file claimed image/png but magic says text/plain
        return False

    # --- IMAGES ---
    if mimetype and mimetype.startswith("image/"):
        return run_with_timeout(_image_deep_check, args=(file_path, mimetype))

    # --- TEXT ---
    if mimetype == "text/plain":
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    return False
                # strict UTF-8 decode for confidence
                chunk.decode("utf-8", errors="strict")
            return True
        except Exception:
            return False

    # --- PDF ---
    if mimetype == "application/pdf":
        return run_with_timeout(_pdf_deep_check, args=(file_path,))

    # --- ZIP ---
    if mimetype == "application/zip":
        return run_with_timeout(_zip_deep_check, args=(file_path,))

    # --- FALLBACK with filetype/libmagic ---
    try:
        if magic is not None:
            mm = _magic_mime(file_path)
            if mm == mimetype:
                return True
    except Exception:
        return False

    # final conservative fallback: reject unknowns
    return False
