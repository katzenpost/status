try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError  # type: ignore

try:
    __version__ = version("katzenpost-status")
except PackageNotFoundError:
    __version__ = "0.2025.12"
