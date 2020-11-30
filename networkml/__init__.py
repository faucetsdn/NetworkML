from pbr.version import VersionInfo

__version__ = VersionInfo('networkml').semantic_version().release_string()
