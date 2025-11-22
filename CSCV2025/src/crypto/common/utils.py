from crypto.common.ec import Point, ECOperations

# A global Elliptic Curve operations instance used for deserialization.
# This provides the necessary curve parameters to reconstruct Point objects.
ec = ECOperations()


def serialize_point(point: Point) -> dict:
    """Converts an elliptic curve Point into a JSON-serializable dictionary.

    This is necessary because custom Point objects cannot be directly encoded
    by standard JSON libraries. The point's coordinates are represented as
    hexadecimal strings for a consistent data transfer format. It also handles
    the special case of the point at infinity.

    Args:
        point: The elliptic curve point to serialize.

    Returns:
        A dictionary representation of the point, or None if the input is None.
    """
    if point is None:
        return None
    if point.is_infinity:
        return {"is_infinity": True, "x": "0x0", "y": "0x0"}
    return {"is_infinity": False, "x": hex(point.x), "y": hex(point.y)}


def deserialize_point(data: dict) -> Point:
    """Reconstructs an elliptic curve Point from its dictionary representation.

    This function is the inverse of serialize_point. It uses the global `ec`
    instance to access the curve parameters required for instantiating the
    Point object.

    Args:
        data: The dictionary representation of the point.

    Returns:
        The deserialized elliptic curve point, or None if the input is None.
    """
    if data is None:
        return None
    if data.get("is_infinity", False):
        return Point.infinity(ec.curve)
    x = int(data["x"], 16)
    y = int(data["y"], 16)
    return Point(x, y, ec.curve)


def serialize_bytes_list(bytes_list) -> list[str]:
    """Converts a list of bytes objects into a list of hex strings for JSON.

    Since raw bytes are not a valid JSON type, this function encodes them
    into a universally recognized string format. It can also gracefully handle
    a single bytes object by wrapping its hex representation in a list.

    Args:
        bytes_list: The list of bytes, or a single bytes object.

    Returns:
        A list of hexadecimal strings, or None if the input is None.
    """
    if bytes_list is None:
        return None
    # Handle the case where a single bytes object is passed instead of a list
    if not isinstance(bytes_list, list):
        return [bytes_list.hex()]
    return [b.hex() if isinstance(b, bytes) else b for b in bytes_list]


def deserialize_bytes_list(hex_list: list[str]) -> list[bytes]:
    """Converts a list of hexadecimal strings back into a list of bytes objects.

    This is the inverse operation of serialize_bytes_list, decoding the string
    representation used for data transfer back into its raw bytes form.

    Args:
        hex_list: The list of hexadecimal strings.

    Returns:
        The deserialized list of bytes objects, or None if the input is None.
    """
    if hex_list is None:
        return None
    return [bytes.fromhex(h) if isinstance(h, str) else h for h in hex_list]
