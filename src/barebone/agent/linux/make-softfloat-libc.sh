#!/bin/sh
#
# Assembles the soft-float sysroot's libc.a from a picolibc build plus the
# compiler-rt builtins, and removes the parts of picolibc the agent replaces.
#
# Two families of members come out. The agent defines malloc and friends over the
# kernel allocator, so picolibc's own allocator would be both redundant and a
# duplicate definition. Its generic memcpy is worse than redundant: it never
# returns for a copy of sixteen bytes or more whose source is misaligned, which
# is what the JavaScript engine does the first time it interns a long string.
#
# Usage:
#   make-softfloat-libc.sh <picolibc-build-dir> <builtins.a> <out-libc.a>
#
# Re-run this whenever the soft-float SDK is rebuilt: a fresh picolibc drops the
# replacements back in and the agent hangs on its first script.

set -eu

if [ $# -ne 3 ]; then
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

picolibc_build=$1
builtins=$2
output=$3

ar=${AR:-llvm-ar}

replaced_by_agent="
libc_stdlib_calloc.c.o
libc_stdlib_free.c.o
libc_stdlib_mallinfo.c.o
libc_stdlib_malloc.c.o
libc_stdlib_malloc-stats.c.o
libc_stdlib_malloc-usable-size.c.o
libc_stdlib_memalign.c.o
libc_stdlib_posix-memalign.c.o
libc_stdlib_realloc.c.o
libc_stdlib_reallocarray.c.o
libc_stdlib_reallocf.c.o
memcpy-stub.c.o
memmove-stub.c.o
"

rm -f "$output"

"$ar" -M <<EOF
create $output
addlib $picolibc_build/libc.a
addlib $builtins
save
end
EOF

for member in $replaced_by_agent; do
    "$ar" d "$output" "$member"
done

"$ar" s "$output"

for member in $replaced_by_agent; do
    if "$ar" t "$output" | grep -qx "$member"; then
        echo "$0: $member survived removal" >&2
        exit 1
    fi
done

echo "$output: $("$ar" t "$output" | wc -l | tr -d ' ') members"
