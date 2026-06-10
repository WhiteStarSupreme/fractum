from typing import Any, List, Union

from src.utils.integrity import get_enhanced_random_bytes


class SecureMemory:
    @staticmethod
    def secure_clear(data: Union[bytes, bytearray, str, List[Any]]) -> None:
        """Zeros mutable sensitive data in place.

        M4: the previous implementation applied multi-pass patterns and called
        gc.collect() / created garbage objects.  None of that is effective in
        CPython because (a) the GC doesn't guarantee memory reuse, (b) bytearray
        multi-pass writes are equivalent to a single zero pass from a security
        standpoint, and (c) it gave a false sense of assurance.

        Important limitation: `bytes` and `str` are *immutable* — this function
        cannot zero the underlying buffer.  All key material MUST be held in a
        `bytearray` so the zero-in-place path is taken.  The callers in
        commands.py have been updated accordingly.
        """
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, list):
            for i in range(len(data)):
                item = data[i]
                if isinstance(item, (bytearray, list)):
                    SecureMemory.secure_clear(item)
                else:
                    try:
                        data[i] = 0
                    except TypeError:
                        data[i] = None
            data.clear()
        # bytes/memoryview/str: immutable — caller should use bytearray for key material

    @classmethod
    def secure_context(cls, size: int = 32) -> "SecureContext":
        return SecureContext(size)

    @staticmethod
    def secure_string() -> str:
        """Returns a 32-character cryptographically secure alphanumeric string."""
        import string as _string
        charset = _string.ascii_letters + _string.digits
        result = []
        # Rejection sampling — no modulo bias
        max_valid = 256 - (256 % len(charset))
        while len(result) < 32:
            for byte in get_enhanced_random_bytes(64):
                if byte < max_valid:
                    result.append(charset[byte % len(charset)])
                    if len(result) == 32:
                        break
        return "".join(result)

    @staticmethod
    def secure_bytes(length: int = 32) -> bytearray:
        """Returns a fresh bytearray filled with cryptographically secure random bytes."""
        return bytearray(get_enhanced_random_bytes(length))


class SecureContext:
    """Context manager for securely handling a temporary sensitive buffer."""

    def __init__(self, size: int = 32) -> None:
        self.buffer = bytearray(get_enhanced_random_bytes(size))
        self.size = size

    def __enter__(self) -> bytearray:
        return self.buffer

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        SecureMemory.secure_clear(self.buffer)
