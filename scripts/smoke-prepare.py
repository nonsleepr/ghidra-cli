#!/usr/bin/env python3
"""Mutating preparation smoke on an isolated, unanalyzed discovery_fixture.rs ELF.

python3 scripts/smoke-prepare.py --project /projects/preparation -- docker exec cli ghidra-cli
"""
import argparse
import json
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--project', required=True)
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
prefix = a.command[1:] if a.command[:1] == ['--'] else a.command
if not prefix:
    p.error('Supply the CLI command after --')


def run(*args, failure=None):
    result = subprocess.run(prefix + ['--json', *args, '--project', a.project,
                                     '--program', 'discovery.elf'],
                            capture_output=True, text=True, timeout=120)
    if failure is not None:
        assert result.returncode != 0 and failure in result.stderr, result
        return None
    assert result.returncode == 0, f'{args}: {result.stderr}'
    return json.loads(result.stdout)


def state():
    return run('script', 'java',
               'println(Long.toString(currentProgram.getListing().getNumInstructions())); '
               'println(Long.toString(currentProgram.getFunctionManager().getFunctionCount())); '
               'println(Long.toString(currentProgram.getSymbolTable().getNumSymbols())); '
               'println(Long.toString(currentProgram.getBookmarkManager().getBookmarkCount()));')['stdout']


def stop():
    subprocess.run(prefix + ['stop', '--project', a.project], check=True, timeout=30)


try:
    before = state()
    run('function', 'prepare', '0x401010', '--max-bytes', '7', failure='escapes preparation window')
    assert before == state(), 'Failed preparation left metadata behind'
    prepared = run('function', 'prepare', '0x401010', 'prepared_smoke', '--max-bytes', '8')
    assert prepared['status'] == 'prepared' and prepared['new_instruction_count'] == 2, prepared
    assert prepared['total_size'] == 8 and not prepared['analysis_run'], prepared
    assert prepared['ranges'] == run('function', 'body', '0x401010')['ranges'], prepared
    assert 'code' in run('decompile', 'prepared_smoke')
    edited = run('function', 'set-signature', 'prepared_smoke', '--signature',
                 'bool prepared_smoke(char *secret, char *key)')
    assert run('function', 'get', 'prepared_smoke')['signature'] == edited['signature']
    stop()
    assert run('function', 'body', 'prepared_smoke')['ranges'] == prepared['ranges']
    assert run('function', 'get', 'prepared_smoke')['signature'] == edited['signature']
    assert run('script', 'java',
               'println(String.valueOf(getInstructionAt(toAddr(0x401018L))));')['stdout'].strip() == 'null'
    print('Bounded preparation, rollback, decompile and persistence checks passed', flush=True)
finally:
    stop()
