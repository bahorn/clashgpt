MAGIC = b'# GRUB Environment Block\n'


def pad_new(value, count=16, val=b'\x90', before=True):
    left = count - len(value)
    if before:
        return left * val + value
    else:
        return value + left * val


def env_block(vars):
    """
    Contructs an enviroment block.
    """
    res = b''
    res += MAGIC
    for key, value in vars.items():
        res += bytes(f'{key}=', 'ascii') + value
    return pad_new(res, count=1024, val=b'#', before=False)
