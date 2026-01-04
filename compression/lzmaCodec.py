import lzma

def compress_bytes(data: bytes) -> bytes:#compress raw byte data using LZMA, this used to reduce storage size and cost before encryption and cloud upload
    return lzma.compress(data)
    #^ apply lossless lzma compression

def decompress_bytes(data: bytes) -> bytes:
    # Decompress compressed lzma byte data
    # restores original
    
    return lzma.decompress(data)
