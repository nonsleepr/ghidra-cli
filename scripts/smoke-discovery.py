#!/usr/bin/env python3
"""Read-only discovery smoke on an imported, unanalyzed discovery_fixture.rs ELF.

Import it with analyzeHeadless ... -import discovery.elf -noanalysis first.
python3 scripts/smoke-discovery.py --project /projects/discovery -- docker exec cli ghidra-cli
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


def run(*args):
    result = subprocess.run(prefix + ['--json', *args, '--project', a.project,
                            '--program', 'discovery.elf'], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f'{args}: {result.stderr}'
    return json.loads(result.stdout)


def diagnostic(*args):
    result = subprocess.run(prefix + [*args, '--json'], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def marker():
    return run('script', 'java', 'println(Long.toString(currentProgram.getModificationNumber()));')['stdout']


try:
    before = marker()
    version = diagnostic('version')
    strings = run('find', 'string', 'DISCOVERYNEEDLE', '--details')
    assert strings['count'] == 3, strings
    assert not strings['search']['truncated'], strings
    # Measure reuse after any required legacy-bridge refresh on the first search.
    initial = diagnostic('status', '--project', a.project)
    assert initial['state'] == 'running', initial
    refs = run('strings', 'refs', 'discoveryneedle', '--discover',
               '--start', '0x401000', '--end', '0x40103f')
    decoded = [r for r in refs['results'] if r['reference_source'] == 'decoded']
    assert len(decoded) == 3 and any(r['interior_offset'] == 7 for r in decoded), refs
    assert not refs['discovery']['truncated'], refs
    instruction = run('disasm', '0x401000', '-n', '1', '--resolve-strings', '--discover')
    assert instruction['references'][0]['string_preview']['value'] == 'Prefix DiscoveryNeedle Tail', instruction
    candidate = run('function', 'candidates', '--address', '0x401003')['results'][0]
    assert candidate['range_end_exclusive'] == '00401008', candidate
    assert candidate['next_indexed_start'] == '00401020', candidate
    assert run('function', 'candidates', '--address', '0x401010')['count'] == 0
    table = run('vtable', 'inspect', '0x405050', '--slots', '5')
    assert table['typeinfo_name'] == '12FixtureClass', table
    assert len(table['slots']) == 5 and table['slots'][2]['status'] == 'null', table
    assert before == marker(), 'Discovery modified the database'
    final = diagnostic('status', '--project', a.project)
    assert final['compatibility']['protocol'] == final['compatibility']['script'] == 'match', final
    assert final['client']['build_id'] == version['build_id'] == final['bridge']['cli_build_id'], final
    assert final['bridge']['current_program'] == 'discovery.elf', final
    assert final['canonical_project'] == final['bridge']['project_path'], final
    assert final['pid'] == initial['pid'] and final['port'] == initial['port'], final
    print('Client/bridge identity and reuse checks passed', flush=True)
    print('Read-only discovery smoke checks passed', flush=True)
finally:
    subprocess.run(prefix + ['stop', '--project', a.project], timeout=30)
