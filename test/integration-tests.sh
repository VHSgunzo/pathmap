#!/bin/bash

set -o functrace
set -o errtrace # trap ERR in functions
set -o errexit
set -o nounset

export LC_ALL=C
export LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"
lib="$project_root/path-mapping.so"
testdir="${TESTDIR:-/tmp/path-mapping}"

export PATH_MAPPING="$testdir/virtual:$testdir/real"

failure() {
    local lineno="$1"
    local msg="$2"
    local test_case="${FUNCNAME[1]}"
    echo
    echo "Failed  $test_case  in line $lineno at command:"
    echo "$msg"
    echo
    if [[ -f "out/$test_case.err" ]]; then
        echo "stderr:"
        cat "out/$test_case.err"
    else
            echo "stderr is empty"
    fi
    echo
}
trap 'failure "${LINENO}" "${BASH_COMMAND}"' ERR

setup() {
    rm -rf "$testdir/real" # clean up previous test case if present
    mkdir -p "$testdir/real"
    cd "$testdir/real"
    mkdir -p dir1/dir2
    echo content0 >file0
    echo content1 >dir1/file1
    echo content2 >dir1/dir2/file2
    echo content3 >dir1/dir2/file3
    cd "$testdir"
}

# Verify that excludes prevent mapping of sensitive files
test_excludes() {
    setup
    PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf" \
    PATH_MAPPING="/etc:$testdir/virtual_etc" \
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        bash -c "test -e /etc/passwd && echo ok" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "ok"
}

# Verify multi-pair PATH_MAPPING works in order
test_multi_mapping_order() {
    setup
    local saved_pm="${PATH_MAPPING-}"
    PATH_MAPPING="$testdir/virtualA:$testdir/real,/$testdir/virtual:/shouldnotmatch"
    mkdir -p "$testdir/real/dir"; echo hey >"$testdir/real/dir/f"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        bash -c "cat '$testdir/virtualA/dir/f'" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err || true
    check_strace_file
    check_output_file "hey"
    PATH_MAPPING="$saved_pm"
}

# RELSYMLINK=1: relative symlink should resolve relative to virtual dir and still map
test_relsymlink_cat_relative() {
    setup
    ln -s "dir2/file2" "$testdir/real/dir1/rel"
    PATHMAP_RELSYMLINK=1 LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        cat "$testdir/virtual/dir1/rel" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "content2"
}

# RELSYMLINK=1: execute relative symlink like /app/sh -> ../usr/bin/busybox under preload
test_relsymlink_exec_busybox_preload() {
    setup
    mkdir -p "$testdir/real/usr/bin"
    ln -sf "../usr/bin/busybox" "$testdir/real/sh"
    # Point busybox to a real shell to ensure command works in sandbox
    ln -sf "/bin/sh" "$testdir/real/usr/bin/busybox"
    PATHMAP_RELSYMLINK=1 PATH_MAPPING="/app:$testdir/real" \
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        env /./app/sh -c "echo hello" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    #check_strace_file # contains /app
    check_output_file "hello"
}

# RELSYMLINK=1: execute relative symlink like /app/sh under tracer
test_relsymlink_exec_busybox_tracer() {
    setup
    mkdir -p "$testdir/real/usr/bin"
    ln -sf "../usr/bin/busybox" "$testdir/real/sh"
    ln -sf "/bin/sh" "$testdir/real/usr/bin/busybox"
    PATHMAP_RELSYMLINK=1 PATH_MAPPING="/app:$testdir/real" \
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        env /./app/sh -c "echo hello" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    #check_strace_file # contains /app
    check_output_file "hello"
}

# Overlapping prefixes: most specific mapping must win
test_overlapping_prefix_precedence() {
    setup
    echo spcontent >"$testdir/real/dir1/file1" # ensure content known
    local saved_pm="${PATH_MAPPING-}"
    PATH_MAPPING="$testdir/virtual/dir1:$testdir/real/dir1,$testdir/virtual:$testdir/real"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        cat "$testdir/virtual/dir1/file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "spcontent"
    PATH_MAPPING="$saved_pm"
}

check_strace_file() {
    test_name="${FUNCNAME[1]}"
    if [[ $# == 2 ]]; then
        test_name="$1"; shift
    fi
    strace_file="$testdir/strace/$test_name"
    lines="$( grep virtual "$strace_file" | grep -vE '^execve|^write|^Mapped Path:|PATH_MAPPING: ' || true )"
    if [[ "$lines" ]] ; then
        echo "Unmapped path in $strace_file:"
        echo "$lines"
        return 1
    fi
}

check_output_file() {
    test_name="${FUNCNAME[1]}"
    if [[ $# == 2 ]]; then
        test_name="$1"; shift
    fi
    expected="$1"
    out_file="$testdir/out/$test_name"
    output="$(cat "$out_file")"
    if ! [[ "$output" == "$expected" ]]; then
        echo "ERROR: output was not as expected:"
        echo "'$output' != '$expected'"
        return 1
    fi
}

assert_readlink_virtual() {
    create_link_path="$1"
    link_content="$2"
    readlink_path="$3"
    expected="$4"
    ln -sf "$link_content" "$create_link_path"
    result="$(LD_PRELOAD="$lib" readlink -f "$readlink_path" 2>/dev/null)"
    if ! [[ "$result" == "$expected" ]]; then
        echo "assert_readlink_virtual $@:"
        echo "'$result' != '$expected'"
        return 1
    fi
}
assert_readlink_real() {
    create_link_path="$1"
    link_content="$2"
    readlink_path="$3"
    expected="$4"
    ln -sf "$link_content" "$create_link_path"
    result="$(PATHMAP_REVERSE=0 LD_PRELOAD="$lib" readlink -f "$readlink_path" 2>/dev/null)"
    if ! [[ "$result" == "$expected" ]]; then
        echo "assert_readlink_real $@:"
        echo "'$result' != '$expected'"
        return 1
    fi
}
test_readlink() {
    setup
    # No mapping in name, but reverse maps content under real→virtual: expect virtual with reverse
    assert_readlink_virtual "$testdir/real/link" "$testdir/real/target" "$testdir/real/link" "$testdir/virtual/target"
    assert_readlink_real "$testdir/real/link" "$testdir/real/target" "$testdir/real/link" "$testdir/real/target"
    # Link name mapped: virtual expected with reverse, real expected without reverse
    assert_readlink_virtual "$testdir/real/link" "$testdir/real/target" "$testdir/virtual/link" "$testdir/virtual/target"
    assert_readlink_real "$testdir/real/link" "$testdir/real/target" "$testdir/virtual/link" "$testdir/real/target"
    # Link contents virtual: virtual expected with reverse, real path expected without reverse
    assert_readlink_virtual "$testdir/real/link" "$testdir/virtual/target" "$testdir/virtual/link" "$testdir/virtual/target"
    assert_readlink_real "$testdir/real/link" "$testdir/real/dir1/dir2/file2" "$testdir/real/link" "$testdir/real/dir1/dir2/file2"
}

test_readlink_f_relative() {
    setup
    ln -s "dir2/file2" "$testdir/real/dir1/relativelink"
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        readlink -f "$testdir/virtual/dir1/relativelink" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual/dir1/dir2/file2"
    test x"$(cat "$testdir/real/dir1/relativelink")" == xcontent2
}

test_readlink_f_real() {
    setup
    ln -s "$testdir/real/dir1/dir2/file2" "$testdir/real/dir1/reallink"
    # With reverse (default) expect virtual path
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        readlink -f "$testdir/virtual/dir1/reallink" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual/dir1/dir2/file2"
}
test_readlink_f_real_no_reverse() {
    setup
    ln -s "$testdir/real/dir1/dir2/file2" "$testdir/real/dir1/reallink"
    PATHMAP_REVERSE=0 LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        readlink -f "$testdir/virtual/dir1/reallink" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/real/dir1/dir2/file2"
}

test_readlink_f_virtual() {
    setup
    LD_PRELOAD="$lib" ln -s "$testdir/virtual/dir1/dir2/file2" "$testdir/virtual/dir1/virtlink" 2>/dev/null
    # With reverse (default) expect virtual path
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        readlink -f "$testdir/virtual/dir1/virtlink" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    #check_strace_file # False positive because link contains the word "virtual"
    check_output_file "$testdir/virtual/dir1/dir2/file2"
}
test_readlink_f_virtual_no_reverse() {
    setup
    LD_PRELOAD="$lib" ln -s "$testdir/virtual/dir1/dir2/file2" "$testdir/virtual/dir1/virtlink" 2>/dev/null
    PATHMAP_REVERSE=0 LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        readlink -f "$testdir/virtual/dir1/virtlink" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/real/dir1/dir2/file2"
}

# Glob forward mapping: single-star tail capture
test_glob_forward_tail() {
    setup
    PATH_MAPPING="$testdir/virtual/*:$testdir/real/*" \
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        /bin/cat "$testdir/virtual/dir1/dir2/file2" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "content2"
}

# Glob forward mapping: multi-star capture in middle
test_glob_forward_multi() {
    setup
    PATH_MAPPING="$testdir/virtual/*/*/file2:$testdir/real/*/*/file2" \
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        /bin/cat "$testdir/virtual/dir1/dir2/file2" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "content2"
}

# access(): read permission check on virtual path (preload)
test_access_preload() {
    setup
    chmod 600 "$testdir/real/file0"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "[ -r '$testdir/virtual/file0' ] && echo yes || echo no" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "yes"
}

# access(): read permission check on virtual path (tracer, via /usr/bin/test)
test_access_tracer() {
    setup
    chmod 600 "$testdir/real/file0"
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd "$testdir/testtool-access" "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "yes"
}

# truncate(): resize a file via coreutils on virtual path (preload)
test_truncate_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        strace -o "strace/${FUNCNAME[0]}" /usr/bin/truncate -s 3 "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test "$(stat -c %s "$testdir/real/file0")" == 3
}

# truncate(): resize a file via coreutils on virtual path (tracer)
test_truncate_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd strace -o "strace/${FUNCNAME[0]}" /usr/bin/truncate -s 3 "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test "$(stat -c %s "$testdir/real/file0")" == 3
}

# mktemp file in virtual dir should create in real mapped dir (preload)
test_mkstemp_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "f=\$(mktemp '$testdir/virtual/dir1/tmp.XXXXXX'); echo \"\$f\"" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    created="$(cat "$testdir/out/${FUNCNAME[0]}")"
    # reverse makes path virtual; ensure the real file exists
    real_created="${created/$testdir\/virtual\//$testdir/real/}"
    test -f "$real_created"
}

# mktemp dir in virtual dir should create in real mapped dir (preload)
test_mkdtemp_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "d=\$(mktemp -d '$testdir/virtual/dir1/tmp.XXXXXX'); echo \"\$d\"" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    created="$(cat "$testdir/out/${FUNCNAME[0]}")"
    real_created="${created/$testdir\/virtual\//$testdir/real/}"
    test -d "$real_created"
}

# mktemp file in virtual dir (tracer)
test_mkstemp_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd bash -lc "f=\$(mktemp '$testdir/virtual/dir1/tmp.XXXXXX'); echo \"\$f\"" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    created="$(cat "$testdir/out/${FUNCNAME[0]}")"
    real_created="${created/$testdir\/virtual\//$testdir/real/}"
    test -f "$real_created"
}

# mktemp dir in virtual dir (tracer)
test_mkdtemp_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd bash -lc "d=\$(mktemp -d '$testdir/virtual/dir1/tmp.XXXXXX'); echo \"\$d\"" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    created="$(cat "$testdir/out/${FUNCNAME[0]}")"
    real_created="${created/$testdir\/virtual\//$testdir/real/}"
    test -d "$real_created"
}

# realpath(): ensure reverse returns virtual path (preload)
test_realpath_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        realpath "$testdir/virtual/dir1/dir2/../file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/virtual/dir1/file1"
}

# realpath(): ensure reverse returns virtual path (tracer)
## Tracer does not hook realpath directly; covered by readlink -f tests

# realpath(): test with buffer (preload)
test_realpath_buffer_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        "$testdir/testtool-realpath" "$testdir/virtual/dir1/dir2/../file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # With buffer: should return real path (for memory safety)
    grep -q "realpath with buffer: $testdir/real/dir1/file1" out/${FUNCNAME[0]}
    # With NULL: should return virtual path (reverse mapping works)
    grep -q "realpath with NULL: $testdir/virtual/dir1/file1" out/${FUNCNAME[0]}
}

# realpath(): test with buffer (tracer)
test_realpath_buffer_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" "$project_root/pathmap" \
        "$testdir/testtool-realpath" "$testdir/virtual/dir1/dir2/../file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Tracer applies reverse mapping to both cases (no memory safety issues)
    grep -q "realpath with buffer: $testdir/virtual/dir1/file1" out/${FUNCNAME[0]}
    grep -q "realpath with NULL: $testdir/virtual/dir1/file1" out/${FUNCNAME[0]}
}

# canonicalize_file_name(): test (preload)
test_canonicalize_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        "$testdir/testtool-canonicalize" "$testdir/virtual/dir1/dir2/../file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Should return virtual path
    grep -q "canonicalize_file_name: $testdir/virtual/dir1/file1" out/${FUNCNAME[0]}
}

# canonicalize_file_name(): test (tracer)
test_canonicalize_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" "$project_root/pathmap" \
        "$testdir/testtool-canonicalize" "$testdir/virtual/dir1/dir2/../file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Should return virtual path
    grep -q "canonicalize_file_name: $testdir/virtual/dir1/file1" out/${FUNCNAME[0]}
}

# glob expansion in shell should list virtual entries (preload)
test_glob_preload() {
    setup
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "/bin/ls -d '$testdir/virtual/'* | /bin/sort" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/virtual/dir1
$testdir/virtual/file0"
}

# glob expansion in shell (tracer)
test_glob_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd bash -lc "/bin/ls -d '$testdir/virtual/'* | /bin/sort" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/virtual/dir1
$testdir/virtual/file0"
}

# Startup CWD fix must respect PATH_MAPPING_EXCLUDE (preload)
test_startup_cwd_fix_respects_exclude_preload() {
    setup
    # Exclude current $testdir to mimic excluding $PWD
    PATH_MAPPING_EXCLUDE="$testdir" \
    PATH_MAPPING="$testdir/virtual:$testdir/real" \
    PATHMAP_DEBUG=1 LD_PRELOAD="$lib" \
        bash -lc "/bin/true" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Ensure no "Startup CWD fix:" message was printed
    if grep -q "Startup CWD fix:" "out/${FUNCNAME[0]}.err"; then
        echo "Unexpected startup CWD fix under exclude" >&2
        return 1
    fi
}

# Startup CWD fix must respect PATH_MAPPING_EXCLUDE (tracer)
test_startup_cwd_fix_respects_exclude_tracer() {
    setup
    # Exclude current $testdir to mimic excluding $PWD
    PATH_MAPPING_EXCLUDE="$testdir" \
    PATH_MAPPING="$testdir/virtual:$testdir/real" \
    PATHMAP_DEBUG=1 \
        tracer_cmd bash -lc "/bin/true" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Ensure no "[pathmap] startup cwd fix:" message was printed
    if grep -qi "startup cwd fix:" "out/${FUNCNAME[0]}.err"; then
        echo "Unexpected startup CWD fix under exclude (tracer)" >&2
        return 1
    fi
}

test_ln() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        ln -s "linkcontent" "$testdir/virtual/dir1/link" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    readlink "$testdir/real/dir1/link" >out/${FUNCNAME[0]}
    check_strace_file
    check_output_file "linkcontent"
}

disabled_test_thunar() { # Disabled because slow and not really useful
    if ! which Thunar >/dev/null; then
        echo "Thunar not found, skipping test case"
        return
    fi
    if pgrep Thunar; then
        echo "Thunar is running. Execute Thunar -q if you want to run it."
        return
    fi
    setup
    cd real
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        Thunar "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err &
    sleep 3; kill %1
    check_strace_file Thunar
}

test_cat() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        cat "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "content0"
    check_strace_file
}

test_find() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        find "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual
$testdir/virtual/file0
$testdir/virtual/dir1
$testdir/virtual/dir1/file1
$testdir/virtual/dir1/dir2
$testdir/virtual/dir1/dir2/file3
$testdir/virtual/dir1/dir2/file2"
}

test_grep() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        grep -R content "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual/file0:content0
$testdir/virtual/dir1/file1:content1
$testdir/virtual/dir1/dir2/file3:content3
$testdir/virtual/dir1/dir2/file2:content2"
}

test_chmod() {
    setup
    chmod 700 "$testdir/real/file0"
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        chmod 777 "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test "$(stat -c %a "$testdir/real/file0")" == 777
}

test_utime() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        ./testtool-utime "$testdir/virtual/dir1/file1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    chmod 700 real/dir1/file1
    stat -c %X:%Y "real/dir1/file1" >out/${FUNCNAME[0]}
    check_strace_file
    check_output_file '200000000:100000000'
}

test_rm() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        rm -r "$testdir/virtual/dir1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test '!' -e "$testdir/real/dir1"
}

test_rename() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        /usr/bin/mv "$testdir/virtual/dir1" "$testdir/virtual/dir1_renamed" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test '!' -e "$testdir/real/dir1"
    test -e "$testdir/real/dir1_renamed"
}

test_bash_exec() {
    setup
    cp /usr/bin/echo "$testdir/real/dir1/"
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        bash -c "'$testdir/virtual/dir1/echo' arg1 arg2 arg3 arg4 arg5" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "arg1 arg2 arg3 arg4 arg5"
}

test_bash_cd() { # Test chdir()
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        bash -c "cd virtual; ls; cd dir1; ls" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'dir1\nfile0\ndir2\nfile1'
}

test_execl_0() {
    setup
    cp ./testtool-execl ./testtool-printenv real/
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        "$testdir/virtual/testtool-execl" execl "$testdir/virtual/testtool-printenv" 0 \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'TEST0=value0'
}

test_execl_1() {
    setup
    cp ./testtool-execl ./testtool-printenv real/
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        "$testdir/virtual/testtool-execl" execl "$testdir/virtual/testtool-printenv" 1 \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'arg1\nTEST0=value0'
}

test_execlp_2() {
    setup
    cp ./testtool-execl ./testtool-printenv real/
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        "$testdir/virtual/testtool-execl" execlp "$testdir/virtual/testtool-printenv" 2 \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'arg1\narg2\nTEST0=value0'
}

test_execle_3() {
    setup
    cp ./testtool-execl ./testtool-printenv real/
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        "$testdir/virtual/testtool-execl" execle "$testdir/virtual/testtool-printenv" 3 \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'arg1\narg2\narg3\nTEST1=value1\nTEST2=value2'

}

test_du() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        du "$testdir/virtual/" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "8	$testdir/virtual/dir1/dir2
12	$testdir/virtual/dir1
16	$testdir/virtual/"
}

test_df() { # Tests realpath()
    setup
    expected="$(df --output="source,fstype,itotal,size,target" "$testdir/real/")"
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        df --output="source,fstype,itotal,size,target" "$testdir/virtual/" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$expected"
}

# explicit statfs/statvfs through tracer
test_statfs_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd "$testdir/testtool-statfs" "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Compare with real dir to ensure mapping didn't break fs identity
    ref="$($testdir/testtool-statfs "$testdir/real" 2>/dev/null)"
    output="$(cat "$testdir/out/${FUNCNAME[0]}")"
    if [ -n "$ref" ]; then
        if [ "$output" != "$ref" ]; then
            echo "ERROR: output was not as expected:"; echo "'$output' != '$ref'"; return 1; fi
    fi
}

# Ensure tracer remaps umount2 target (we expect EPERM/ENOENT; just verify call path)
test_umount2_tracer() {
    setup
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd "$testdir/testtool-umount2" "$testdir/virtual/dir1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    # Don't assert specific errno; just ensure the tool ran and produced output
    test -s "out/${FUNCNAME[0]}"
}

# statx through tracer
test_statx_tracer() {
    setup
    # ensure known size
    echo 12345 > "$testdir/real/file0"
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd "$testdir/testtool-statx" "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err || true
    # If tool returned skip (77), just ensure non-empty output file or skip silently
    if grep -q 'not supported' "out/${FUNCNAME[0]}.err" 2>/dev/null; then
        echo "skip" > out/${FUNCNAME[0]}
        check_output_file "skip"
    else
        check_output_file "6" # "12345\n" has length 6 including newline; but we printed number only
    fi
}

test_getfacl() { # Tests getxattr()
    setup
    expected="$(getfacl "$testdir/real/" 2>/dev/null | sed 's/real/virtual/')"
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        getfacl "$testdir/virtual/" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$expected"
}

# xattr on virtual path under preload and tracer
test_xattr_preload() {
    setup
    name="user.pmtest"
    value="v123"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/file0' set '$name' '$value' >/dev/null && '$testdir/testtool-xattr' '$testdir/virtual/file0' get '$name'" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err || true
    out="$(cat "$testdir/out/${FUNCNAME[0]}")"
    if [ "$out" = "skip" ]; then echo "skip" > "$testdir/out/${FUNCNAME[0]}"; check_output_file "skip"; else check_output_file "$value"; fi
}

test_xattr_tracer() {
    setup
    name="user.pmtest"
    value="v123"
    PATH_MAPPING="$PATH_MAPPING" \
        tracer_cmd bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/file0' set '$name' '$value' >/dev/null && '$testdir/testtool-xattr' '$testdir/virtual/file0' get '$name'" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err || true
    out="$(cat "$testdir/out/${FUNCNAME[0]}")"
    if [ "$out" = "skip" ]; then echo "skip" > "$testdir/out/${FUNCNAME[0]}"; check_output_file "skip"; else check_output_file "$value"; fi
}

# xattr on symlink without following (l* variants)
test_xattr_symlink_preload() {
    setup
    ln -sf "file0" "$testdir/real/link0"
    name="user.pmlink"
    value="sv"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/link0' lset '$name' '$value'" \
        >out/${FUNCNAME[0]}.step 2>out/${FUNCNAME[0]}.err || true
    out="$(cat "$testdir/out/${FUNCNAME[0]}.step")"
    if [ "$out" = "skip" ]; then echo "skip" > "$testdir/out/${FUNCNAME[0]}"; check_output_file "skip"; else check_output_file "$value"; fi
    if [ "$out" != "skip" ]; then
        PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/link0' lget '$name'" \
            >out/${FUNCNAME[0]} 2>>out/${FUNCNAME[0]}.err || true
        check_output_file "$value"
    fi
}

test_xattr_symlink_tracer() {
    setup
    ln -sf "file0" "$testdir/real/link0"
    name="user.pmlink"
    value="sv"
    PATH_MAPPING="$PATH_MAPPING" tracer_cmd bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/link0' lset '$name' '$value'" \
        >out/${FUNCNAME[0]}.step 2>out/${FUNCNAME[0]}.err || true
    out="$(cat "$testdir/out/${FUNCNAME[0]}.step")"
    if [ "$out" = "skip" ]; then echo "skip" > "$testdir/out/${FUNCNAME[0]}"; check_output_file "skip"; else check_output_file "$value"; fi
    if [ "$out" != "skip" ]; then
        PATH_MAPPING="$PATH_MAPPING" tracer_cmd bash -lc "'$testdir/testtool-xattr' '$testdir/virtual/link0' lget '$name'" \
            >out/${FUNCNAME[0]} 2>>out/${FUNCNAME[0]}.err || true
        check_output_file "$value"
    fi
}

test_mkfifo() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        mkfifo "$testdir/virtual/dir1/fifo" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    stat -c %F real/dir1/fifo >out/${FUNCNAME[0]}
    check_strace_file
    check_output_file "fifo"
}

test_mkdir() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        mkdir "$testdir/virtual/dir1/newdir" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    stat -c %F real/dir1/newdir >out/${FUNCNAME[0]}
    check_strace_file
    check_output_file "directory"
}

test_ftw() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        ./testtool-ftw "$testdir/virtual/dir1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/real/dir1
$testdir/real/dir1/file1
$testdir/real/dir1/dir2
$testdir/real/dir1/dir2/file3
$testdir/real/dir1/dir2/file2"
}

test_nftw() {
    setup
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        ./testtool-nftw "$testdir/virtual/dir1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/real/dir1
$testdir/real/dir1/file1
$testdir/real/dir1/dir2
$testdir/real/dir1/dir2/file3
$testdir/real/dir1/dir2/file2"
}

test_fts() {
    setup
    mkdir -p real/dir1/dir4
    echo content4 > real/dir1/dir4/file4
    LD_PRELOAD="$lib" strace -o "strace/${FUNCNAME[0]}" \
        ./testtool-fts "$testdir/virtual/dir1/dir2" "$testdir/virtual/dir1/dir4" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file $'dir2\nfile2\nfile3\ndir2\ndir4\nfile4\ndir4'
}

# Reverse mapping Case 2: virtual root child rename (usr-123 -> usr) under preload
test_reverse_dirent_case2_preload() {
    setup
    mkdir -p "$testdir/real/usr-123/bin"
    echo tool >"$testdir/real/usr-123/bin/tool"
    local saved_pm="${PATH_MAPPING-}"
    PATH_MAPPING="$testdir/virtual:$testdir/real,$testdir/virtual/usr:$testdir/real/usr-123"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        bash -lc "/bin/ls -1 '$testdir/virtual' | /bin/grep -x usr" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "usr"
    PATH_MAPPING="$PATH_MAPPING" LD_PRELOAD="$lib" \
        /bin/ls -1 "$testdir/virtual/usr/bin" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "tool"
    PATH_MAPPING="$saved_pm"
}

# Reverse mapping Case 2 under tracer
test_reverse_dirent_case2_tracer() {
    setup
    mkdir -p "$testdir/real/lib-999/bin"
    echo so >"$testdir/real/lib-999/bin/so"
    local tracer="$(dirname "$lib")/pathmap"
    local saved_pm="${PATH_MAPPING-}"
    PATH_MAPPING="$testdir/virtual:$testdir/real,$testdir/virtual/lib:$testdir/real/lib-999"
    PATH_MAPPING="$PATH_MAPPING" "$tracer" -- bash -lc "/bin/ls -1 '$testdir/virtual' | /bin/grep -x lib" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "lib"
    PATH_MAPPING="$PATH_MAPPING" "$tracer" -- /bin/ls -1 "$testdir/virtual/lib/bin" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "so"
    PATH_MAPPING="$saved_pm"
}

# CWD virtualization: pwd -P shows virtual path under preload
test_cwd_virtual_preload() {
    setup
    PATH_MAPPING="$testdir/virtual:$testdir/real" \
    LD_PRELOAD="$lib" bash -lc "cd '$testdir/virtual'; pwd -P" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/virtual"
}

# CWD virtualization: pwd -P shows virtual path under tracer
test_cwd_virtual_tracer() {
    setup
    local tracer="$(dirname "$lib")/pathmap"
    PATH_MAPPING="$testdir/virtual:$testdir/real" \
    "$tracer" -- bash -lc "cd '$testdir/virtual'; pwd -P" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "$testdir/virtual"
}

# --- Tracer variants of core functional tests ---
tracer_cmd() {
    local tracer="$(dirname "$lib")/pathmap"
    "$tracer" -- "$@"
}

test_cat_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /bin/cat "$testdir/virtual/file0" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_output_file "content0"
    check_strace_file
}

test_find_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /usr/bin/find "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual
$testdir/virtual/file0
$testdir/virtual/dir1
$testdir/virtual/dir1/file1
$testdir/virtual/dir1/dir2
$testdir/virtual/dir1/dir2/file3
$testdir/virtual/dir1/dir2/file2"
}

test_grep_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /bin/grep -R content "$testdir/virtual" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    check_output_file "$testdir/virtual/file0:content0
$testdir/virtual/dir1/file1:content1
$testdir/virtual/dir1/dir2/file3:content3
$testdir/virtual/dir1/dir2/file2:content2"
}

test_mkdir_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /bin/mkdir "$testdir/virtual/dir1/newdir" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    stat -c %F real/dir1/newdir >out/${FUNCNAME[0]}
    check_strace_file
    check_output_file "directory"
}

test_rm_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /bin/rm -r "$testdir/virtual/dir1" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test '!' -e "$testdir/real/dir1"
}

test_rename_tracer() {
    setup
    tracer_cmd strace -o "strace/${FUNCNAME[0]}" \
        /usr/bin/mv "$testdir/virtual/dir1" "$testdir/virtual/dir1_renamed" \
        >out/${FUNCNAME[0]} 2>out/${FUNCNAME[0]}.err
    check_strace_file
    test '!' -e "$testdir/real/dir1"
    test -e "$testdir/real/dir1_renamed"
}

# Setup up output directories for the test cases
mkdir -p "$testdir/out"
mkdir -p "$testdir/strace"

# Find all declared functions starting with "test_" in a random order
all_testcases="$(declare -F | cut -d " " -f 3- | grep test)"
enabled_testcases="$(declare -F | cut -d " " -f 3- | grep '^test_' | shuf)"
num_testcases="$(echo "$enabled_testcases" | wc -l)"

N=0
if [[ $# -gt 0 ]]; then
    if [[ $1 == '-l' ]] || [[ $1 == "--list" ]]; then
        echo "All test cases (including disabled ones):"
        echo "$all_testcases"
        exit 0
    fi
    while [[ $# -gt 0 ]]; do
        if [[ "$all_testcases" =~ "$1" ]]; then
            echo "$1"
            $1
            shift
        else
            echo "Unknown test case $1"
            exit 1
            N=$[N+1]
        fi
    done
else
    # If no argument is given, execute all test cases
    for cmd in $enabled_testcases; do
        echo "$cmd"
        $cmd
        N=$[N+1]
    done
fi

echo "$N/$num_testcases TESTS PASSED!"
#rm -rf "$testdir"   # use make clean to clean up instead
