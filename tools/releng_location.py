import os
from pathlib import Path
from typing import Iterator


SOURCE_ROOT = Path(__file__).resolve().parent.parent


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

    local_releng = SOURCE_ROOT / "releng"
    if releng_location_exists(local_releng):
        yield local_releng


def releng_location_exists(location: Path) -> bool:
    return (location / "frida_version.py").exists()


if __name__ == "__main__":
    print(next(enumerate_releng_locations()))
