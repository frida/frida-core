import os
from pathlib import Path
import sys
from typing import Iterator


REPO_DIR = Path(__file__).resolve().parent.parent


def detect_version() -> str:
    releng_location = next(enumerate_releng_locations(), None)
    if releng_location is not None:
        sys.path.insert(0, str(releng_location.parent))
        from releng.frida_version import detect
        version = detect(REPO_DIR).name
    else:
        version = "0.0.0"
    return version


def enumerate_releng_locations() -> Iterator[Path]:
    val = os.environ.get("FRIDA_RELENG")
    if val is not None:
        custom_releng = Path(val)
        if releng_location_exists(custom_releng):
            yield custom_releng

    val = os.environ.get("MESON_SOURCE_ROOT")
    if val is not None:
        parent_releng = Path(val) / "releng"
        if releng_location_exists(parent_releng):
            yield parent_releng

    local_releng = REPO_DIR / "releng"
    if releng_location_exists(local_releng):
        yield local_releng


def releng_location_exists(location: Path) -> bool:
    return (location / "frida_version.py").exists()


if __name__ == "__main__":
    print(detect_version())
