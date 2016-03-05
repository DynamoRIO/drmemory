#!/system/bin/sh
# There's no DT_RPATH support on Android so we have a script set the load path.
home="${0%/*}/.."
# We need $@ to preserve quoted tokens (as opposed to $*)
LD_LIBRARY_PATH=$home/dynamorio/lib32/@build_type@ $home/bin/launcher "$@"
