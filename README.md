# ClashGPT - bah / January 2025

This is an exploit for a bug in GRUB2 that was fixed in January 2025.
It was found, reported and patched by me.

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

```
RSP - (region + size)
0xbff10518 - (0xbfe00000+987072) = 128344
```


lsefimmap:
```
Type      Physical start  - end             #Pages        Size Attributes
ldr-code  00000000bfe00000-00000000bfef0fff 000000f1    964KiB UC WC WT WB
BS-data   00000000bfef1000-00000000bff10fff 00000020    128KiB UC WC WT WB
```

The protective MBR is the best way to get control.

so goal is just to get the target struct to be under our fake mbr / top block
