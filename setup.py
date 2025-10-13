from pathlib import Path
from setuptools import setup, find_packages


def read_readme() -> str:
    readme_path = Path(__file__).resolve().parent / "README.md"
    return readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""


setup(
    name="basefwx",
    version="3.3.1",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "numpy>=1.24.0",
        "pillow>=10.0.0",
        "pqcrypto>=0.3.4",
    ],
    python_requires=">=3.10",
    author="F1xGOD",
    author_email="f1xgodim@gmail.com",
    description="With BaseFWX you can encode securely!",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
)
