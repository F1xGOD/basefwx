from pathlib import Path
from setuptools import setup, find_packages


def read_readme() -> str:
    readme_path = Path(__file__).resolve().parent / "README.md"
    return readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""


def read_version() -> str:
    """Locate the VERSION file in both the dev tree and the
    sdist-extracted layout.

    Dev tree:    repo/VERSION, setup.py at repo/python/setup.py
                 -> Path(__file__).parents[1] / "VERSION"
    Sdist build: basefwx-X.Y.Z/VERSION, setup.py at basefwx-X.Y.Z/setup.py
                 -> Path(__file__).parent / "VERSION"

    Probing both makes `python -m build` (sdist then wheel-from-sdist)
    work without a per-stage hack — previously the wheel build choked on
    `parents[1] / VERSION` because the sdist tarball flattens setup.py
    and VERSION into the same directory.
    """
    here = Path(__file__).resolve()
    candidates = (
        here.parent / "VERSION",      # sdist-extracted layout
        here.parents[1] / "VERSION",  # dev tree
    )
    for candidate in candidates:
        if candidate.is_file():
            value = candidate.read_text(encoding="utf-8").strip()
            if value:
                return value
    raise FileNotFoundError(
        "VERSION not found; checked: " + ", ".join(str(c) for c in candidates)
    )


setup(
    name="basefwx",
    version=read_version(),
    packages=find_packages(),
    # Keep these in sync with pyproject.toml [project].dependencies /
    # [project].optional-dependencies. setuptools emits a warning when
    # pyproject.toml overwrites these — that's expected because we ship
    # pyproject.toml as the source of truth, but having matching values
    # here keeps `pip install -e .` (which still consults setup.py
    # directly on some toolchains) from producing a different graph.
    install_requires=[
        "cryptography>=41.0.0",
        "numpy>=1.24.0",
        "pillow>=10.0.0",
        "pqcrypto>=0.3.4",
        # Argon2id is the default user-KDF for password-based encryption
        # paths (see SECURITY.md and Constants.USER_KDF_DEFAULT in
        # legacy.py). Forcing argon2-cffi as a hard dep matches that
        # default — `pip install basefwx` should give users an Argon2id
        # build, not silently downgrade to PBKDF2. The `[argon2]` extra
        # remains a no-op for back-compat with anyone scripted to it.
        "argon2-cffi>=23.1.0",
    ],
    extras_require={
        "argon2": [],  # kept for compat; argon2-cffi is now a hard dep
    },
    python_requires=">=3.10",
    author="F1xGOD",
    author_email="f1xgodim@gmail.com",
    description="The encryption you can trust, the performance you need, the security you deserve.",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    license="GPL-3.0-or-later",
)
