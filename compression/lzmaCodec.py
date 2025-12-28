import lzma

def compress_bytes(data: bytes) -> bytes:
    return lzma.compress(data)

def decompress_bytes(data: bytes) -> bytes:
    return lzma.decompress(data)
