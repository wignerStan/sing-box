# Generated vendor materializations

`vendor/` contains parent-owned ordinary files generated from exact
`third_party/` source pins plus the ordered patch stacks in `patches/`.

Do not edit these files directly. Run:

```sh
python3 tools/vendor/materialize.py
python3 tools/vendor/verify.py
```

The source relationship, patch digests, patched Git tree, and materialized tree
digest are recorded in `deps/vendor-lock.json`. No Git metadata, gitlink,
submodule, or nested repository is permitted below `vendor/`.
