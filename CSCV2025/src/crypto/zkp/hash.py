from typing import List
import hashlib

HASH_INPUT_DELIMITER = b"$"


def sha512_256_util(h, in_data: List[bytes]) -> bytes:
    """Helper function to hash a list of byte strings."""
    if not in_data:
        return None
    data = bytearray()
    for b in in_data:
        data.extend(b)
        data.extend(HASH_INPUT_DELIMITER)
    h.update(data)
    return h.digest()


def sha512_256(*in_data: bytes) -> bytes:
    """Computes the SHA-512/256 hash of one or more byte strings.

    Inputs are unambiguously joined with a delimiter before hashing to prevent
    collisions between different combinations of inputs (e.g., H(a,b) != H(ab)).
    """
    h = hashlib.new("sha512_256")
    return sha512_256_util(h, list(in_data))


def sha512_256i(*in_data: int) -> int:
    """Computes the SHA-512/256 hash of one or more integers.

    Each integer is converted to its minimal big-endian byte representation
    before being securely joined and hashed. The result is returned as an integer.
    """
    h = hashlib.new("sha512_256")
    # Convert each integer to its minimal byte representation.
    # An explicit check for 0 is needed as (0).bit_length() is 0.
    ptrs = [
        i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b"" for i in in_data
    ]
    hashed_bytes = sha512_256_util(h, ptrs)
    return int.from_bytes(hashed_bytes, "big")


def sha512_256i_tagged(tag: bytes, *in_data: int) -> int:
    """Computes a domain-separated SHA-512/256 hash of one or more integers.

    This "tagged" hash provides domain separation, ensuring that hashes intended
    for one purpose cannot be reused for another. The construction is a common
    pattern: H(H(tag) || H(tag) || data).
    """
    tag_bz = sha512_256(tag)
    h = hashlib.new("sha512_256")
    h.update(tag_bz)
    h.update(tag_bz)
    ptrs = [
        i.to_bytes((i.bit_length() + 7) // 8, "big") if i != 0 else b"" for i in in_data
    ]
    hashed_bytes = sha512_256_util(h, ptrs)
    return int.from_bytes(hashed_bytes, "big")
