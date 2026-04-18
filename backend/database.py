# This file is deprecated. All database configuration is now in backend/app/core/database.py
# Keeping this file for backward compatibility only - DO NOT USE

import warnings

warnings.warn(
    "backend/database.py is deprecated. Use backend/app/core/database.py instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export for backward compatibility only
from app.core.database import (
    Base,
    get_db,
    get_engine,
    get_sessionmaker,
    init_engine,
    SATimeoutError,
)

__all__ = ["Base", "get_db", "get_engine", "get_sessionmaker", "init_engine", "SATimeoutError"]
