# Reading settings from the environment (.env, Docker), kept in safe ranges.
import os


def env_int(name: str, default: int, minimum: int = 1, maximum: int = 100) -> int:
    # A whole number from the environment, kept within safe limits.
    # Bad or missing values fall back to the default instead of crashing or disabling a protection.
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))