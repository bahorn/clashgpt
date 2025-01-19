import math
import struct
from util import pad
from consts import GPT_PARTITION_TYPE, BLOCK_SIZE


class DiskBlock:
    """
    A block, so we can just append classes that inherit from this to a list and
    create a fake disk.
    """
    BLOCK_SIZE = BLOCK_SIZE

    def __init__(self, body=b''):
        self._body = body

    def gen(self):
        return bytes(self._body)

    def __bytes__(self):
        res = pad(self.gen(), self.BLOCK_SIZE)
        assert len(res) == self.BLOCK_SIZE
        return res


class MBRPartitionEntry:
    """
    Very basic, just need to set the partition type.
    """

    def __init__(self, part_type):
        self._part_type = part_type

    def __bytes__(self):
        res = bytearray(16)
        res[0x4] = self._part_type
        return bytes(res)


class ProtectiveMBR(DiskBlock):
    SIG = b'\x55\xaa'

    def __init__(self, partitions, base=[0x1]*BLOCK_SIZE):
        self._base = base
        assert len(base) == BLOCK_SIZE
        self._partitions = partitions

    def gen(self):
        res = bytearray(self._base)
        # now the partition table
        partition_table = pad(b''.join(map(bytes, self._partitions)), 64)
        res[446:446+64] = partition_table
        res[510:512] = self.SIG
        return res


class GPTHeader(DiskBlock):
    SIG = b'EFI PART'
    PART_ENTRY_SIZE = 128

    def __init__(self, n_entries):
        self._n_entries = n_entries

    def gen(self):
        res = bytearray([0x00]*BLOCK_SIZE)
        res[0:8] = self.SIG
        # number of partitions.
        res[0x48:0x48+8] = struct.pack('<Q', 2)
        res[0x50:0x50+4] = struct.pack('<I', self._n_entries)
        # size of each partition entry
        res[0x54:0x54+4] = struct.pack('<I', self.PART_ENTRY_SIZE)

        return res


class GPTPartitionEntry:
    def __init__(self, start, end):
        self._start = start
        self._end = end

    def __bytes__(self):
        res = bytearray(128)
        # so its not the empty guid.
        res[0:16] = [i for i in range(16)]
        res[16:32] = [i for i in range(16)]
        res[0x20:0x20+8] = struct.pack('<Q', self._start)
        res[0x28:0x28+8] = struct.pack('<Q', self._end)
        return bytes(res)


class GPTPartitionEntryBlock(DiskBlock):
    """
    Each block can fit up to four partitions.
    """

    def __init__(self, entries):
        self._entries = entries

    def gen(self):
        body = b''.join(map(bytes, self._entries))
        padding = b'\x00' * (BLOCK_SIZE - len(body))
        return body + padding


def data_to_blocks(data):
    if len(data) == 0:
        return []

    setup = []
    count = math.ceil(len(data) / BLOCK_SIZE)
    for i in range(0, count):
        setup.append(DiskBlock(data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]))
    return setup


def layer(partitions, mbr):
    setup = []
    setup += [ProtectiveMBR([
        MBRPartitionEntry(GPT_PARTITION_TYPE)], base=mbr)]
    setup += [GPTHeader(len(partitions))]
    entries = []

    start = 3 + (len(partitions) // 4)

    for i in range(0, len(partitions), 4):
        entries = []
        for partition in partitions[i:i+4]:
            end = start + len(partition)
            entries += [GPTPartitionEntry(start, end)]
            start = end
        setup += [GPTPartitionEntryBlock(entries)]

    for partition in partitions:
        setup += partition

    return setup


def stack(count, data, mbr):
    curr = data_to_blocks(data)
    for i in range(count):
        curr = layer([curr], mbr)
    return curr
