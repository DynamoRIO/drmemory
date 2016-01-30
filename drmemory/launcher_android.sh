#!/system/bin/sh
# There's no DT_RPATH support on Android so we have a script set the load path.
home="${0%/*}/.."
LD_LIBRARY_PATH=$home/dynamorio/lib32/@build_type@ $home/bin/launcher $*
