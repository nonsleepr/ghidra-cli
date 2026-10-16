#!/usr/bin/env python3
"""Test the same behaviors through a native binary or docker exec prefix.

python3 scripts/smoke-runtime.py --project /tmp/new-project -- target/debug/ghidra-cli
python3 scripts/smoke-runtime.py --project /projects/smoke --fixture /binaries/sample_binary \
    --script /smoke/RuntimeProbe.java -- docker exec ghidra-cli ghidra-cli
"""
import argparse
import json
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--project', required=True, help='New isolated project path visible to the CLI')
p.add_argument('--reuse-project', action='store_true', help='Reuse an isolated project whose import already passed')
p.add_argument('--fixture', default=str(ROOT / 'tests/fixtures/sample_binary'))
p.add_argument('--script', default=str(ROOT / 'tests/fixtures/runtime-scripts/RuntimeProbe.java'))
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
prefix = a.command[1:] if a.command[:1] == ['--'] else a.command
if not prefix:
    p.error('Supply a CLI command after --')
options = ['--project', a.project, '--program', 'sample_binary']


def run(*args, project=True, fail=False):
    argv = prefix + ['--json', *args] + (options if project else [])
    start = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, timeout=240)
    print(f'{args[0:2]}: exit={result.returncode} {time.monotonic()-start:.3f}s', flush=True)
    if fail:
        assert result.returncode != 0, result.stdout
        assert result.stderr.strip(), 'Failure had no diagnostic'
        return
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else None


def java(code):
    return run('script', 'java', code)


# Doctor is human output; require the exit status and pinned runtime.
r = subprocess.run(prefix + ['doctor'], capture_output=True, text=True, timeout=30)
assert r.returncode == 0, r.stdout + r.stderr
assert '12.1.4' in r.stdout, r.stdout
try:
    if a.reuse_project:
        assert run('program', 'info')['name'] == 'sample_binary'
    else:
        run('import', a.fixture)
    run('analyze')
    assert 'code' in run('decompile', 'add_numbers')
    # Xrefs are JSONL, so check separately.
    x = subprocess.run(prefix + ['--json', 'x-ref', 'to', 'add_numbers'] + options,
                       capture_output=True, text=True, timeout=30)
    assert x.returncode == 0 and 'main' in x.stdout, x.stderr
    for _ in range(2):
        value = java('println(currentProgram.getName()); printerr("INLINE_STDERR");')
        assert 'sample_binary' in value['stdout']
        assert 'INLINE_STDERR' in value['stderr']
    # Argument separator follows project options, so invoke this command directly.
    r = subprocess.run(prefix + ['--json', 'script', 'run', a.script] + options + ['--', 'ARGUMENT'],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    value = json.loads(r.stdout)
    assert 'RUNTIME_HELPER:sample_binary:ARGUMENT' in value['stdout']
    assert 'RUNTIME_STDERR' in value['stderr']
    java('var t = new ghidra.program.model.data.TypedefDataType(ghidra.program.model.data.CategoryPath.ROOT, "RuntimeWord", ghidra.program.model.data.UnsignedIntegerDataType.dataType, currentProgram.getDataTypeManager()); currentProgram.getDataTypeManager().addDataType(t, ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);')
    for signature in ['RuntimeWord add_numbers(RuntimeWord *p, char *s)', 'int add_numbers(char *format, ...)']:
        edited = run('function', 'set-signature', 'add_numbers', '--signature', signature)
        assert run('function', 'get', 'add_numbers')['signature'] == edited['signature']
    before = run('function', 'get', 'add_numbers')['signature']
    for signature in ['not a declaration', 'MissingRuntimeType add_numbers(int x)', 'void add_numbers(int duplicate, int duplicate)']:
        run('function', 'set-signature', 'add_numbers', '--signature', signature, fail=True)
        assert run('function', 'get', 'add_numbers')['signature'] == before
    for snippet in ['this is not Java;', 'throw new Exception("EXPECTED_RUNTIME_ERROR");']:
        run('script', 'java', snippet, fail=True)
        assert run('program', 'info')['name'] == 'sample_binary'
    java('getFunction("add_numbers").setComment("before-script");')
    for failure in ['new Exception("EXPECTED_ROLLBACK")', 'new AssertionError("EXPECTED_ROLLBACK")']:
        run('script', 'java', 'getFunction("add_numbers").setComment("failed-script"); throw ' + failure + ';', fail=True)
        assert java('println(getFunction("add_numbers").getComment());')['stdout'].strip() == 'before-script'
    run('script', 'run', '/missing/RuntimeProbe.java', fail=True)
    edited = run('function', 'set-signature', 'add_numbers', '--signature', 'int add_numbers(int left, int right)')
    assert 'left' in run('decompile', 'add_numbers')['code']
    # stop has no --program and emits human output.
    subprocess.run(prefix + ['stop', '--project', a.project], check=True, timeout=30)
    assert run('function', 'get', 'add_numbers')['signature'] == edited['signature']
    assert 'left' in run('decompile', 'add_numbers')['code']
    print('Runtime smoke checks passed', flush=True)
finally:
    subprocess.run(prefix + ['stop', '--project', a.project], timeout=30)
