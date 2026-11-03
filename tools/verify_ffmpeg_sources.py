"""Verify pinned media binaries and source contents; makes no legal certification."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from pathlib import Path
import shutil
import tarfile
import zipfile


DESCRIPTOR = Path(__file__).parent / 'third-party/ffmpeg/source-distribution.json'


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_file(root, name, expected):
    if not name or Path(name).name != name or '\\' in name:
        raise ValueError('Source asset must be a plain filename')
    path = root / name
    if path.is_symlink() or not path.is_file() or sha256(path) != expected:
        raise ValueError('Missing or changed source asset: ' + name)
    return path


def verify(root, descriptor=None):
    root = Path(root).resolve()
    descriptor = descriptor or json.loads(DESCRIPTOR.read_text('utf-8'))
    for item in descriptor['sourceAssets']:
        checked_file(root, item['name'], item['sha256'])
    lock = json.loads(checked_file(root, descriptor['sourceLock']['name'],
                                 descriptor['sourceLock']['sha256']).read_text('utf-8'))
    if (lock['ffmpeg_commit'] != descriptor['ffmpegCommit'] or
            lock['build_recipe_commit'] != descriptor['buildRecipeCommit'] or
            lock['source_cache']['sha256'] != descriptor['sourceCache']['sha256']):
        raise ValueError('Source lock does not match the pinned build')
    components = lock['components']
    if len({item['filename'] for item in components}) != len(components):
        raise ValueError('Duplicate source component')
    expected = {'dependencies/' + item['filename']: item['sha256'] for item in components}
    expected.update({item['arcname']: item['sha256'] for item in lock['supplemental_sources']})
    expected.update({'rust-stdlib-crates/' + item['filename']: item['sha256']
                     for item in lock['rust_std_registry_crates']})
    expected.update({'rust-stdlib-crates/Cargo-' + arch + '.lock': item['sha256']
                     for arch, item in lock['rust_library_locks'].items()})
    supplemental = {}
    seen = set()
    for part in lock['source_parts']:
        archive = checked_file(root, part['filename'], part['sha256'])
        with zipfile.ZipFile(archive) as files:
            names = files.namelist()
            if len(names) != len(set(names)) or set(names) != set(part['members']):
                raise ValueError('Unexpected ZIP members: ' + part['filename'])
            for name in names:
                if name not in expected or name in seen:
                    raise ValueError('Untracked or duplicate source: ' + name)
                with files.open(name) as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != expected[name]:
                    raise ValueError('Source content mismatch: ' + name)
                seen.add(name)
                if name.startswith('supplemental/'):
                    supplemental[name] = files.read(name)
    if seen != set(expected):
        raise ValueError('Incomplete component or supplemental source closure')
    filenames = {item['filename'] for item in components}
    if len(lock['cache_aliases']) != len(components) or set(lock['cache_aliases'].values()) != filenames:
        raise ValueError('Incomplete dependency-cache restore mapping')

    recipes = next(data for name, data in supplemental.items() if '/btbn-build-recipes-' in name)
    with tarfile.open(fileobj=io.BytesIO(recipes), mode='r:gz') as archive:
        scripts = {member.name: archive.extractfile(member).read().decode('utf-8')
                   for member in archive if (member.isfile() or member.issym() or member.islnk()) and '/scripts.d/' in member.name}
    for component in components:
        matches = [text for name, text in scripts.items()
                   if name.rsplit('/', 1)[-1] == component['stage'] + '.sh']
        if not matches and component['stage'] in descriptor['inactiveCacheStages'] and not component['recipe']:
            continue
        if not matches or any(not any(value in text for text in matches)
                              for value in component['recipe'].values()):
            raise ValueError('Component version is absent from pinned recipe: ' + component['stage'])
    cached_stages = {item['stage'] for item in components}
    for name, text in scripts.items():
        if re.search(r'SCRIPT_SKIP=["\']?1', text):
            continue
        if ('SCRIPT_REPO=' in text or 'SCRIPT_URL=' in text) and name.rsplit('/', 1)[-1][:-3] not in cached_stages:
            raise ValueError('Active source download recipe has no archived source: ' + name)

    vendor = next(data for name, data in supplemental.items() if '/rav1e-' in name)
    cargo_checksums = {}
    vendor_files = {}
    cargo_lock = None
    with tarfile.open(fileobj=io.BytesIO(vendor), mode='r:gz') as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name.lstrip('./')
            data = archive.extractfile(member).read()
            if '/vendor/' in '/' + name:
                relative = ('/' + name).split('/vendor/', 1)[1]
                package, path = relative.split('/', 1)
                if path == '.cargo-checksum.json':
                    cargo_checksums[package] = json.loads(data)
                else:
                    vendor_files[(package, path)] = hashlib.sha256(data).hexdigest()
            elif name.rsplit('/', 1)[-1] == 'Cargo.lock':
                cargo_lock = hashlib.sha256(data).hexdigest()
    if cargo_lock != lock['original_rav1e_lock_sha256']:
        raise ValueError('Original rav1e runtime lock is not preserved')
    for crate in lock['rav1e_registry_crates']:
        package = crate['name'] + '-' + crate['version']
        checksum = cargo_checksums.get(package)
        if not checksum or checksum.get('package') != crate['package_sha256']:
            raise ValueError('Missing or altered locked Rust crate: ' + package)
        for name, expected_hash in checksum['files'].items():
            if vendor_files.get((package, name)) != expected_hash:
                raise ValueError('Rust crate content mismatch: ' + package + '/' + name)

    notices = checked_file(root, lock['notices']['filename'], lock['notices']['sha256'])
    with zipfile.ZipFile(notices) as archive:
        names = archive.namelist()
        notice_names = set(names)
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError('Corrupt or duplicate license notice files')
        for identifier, item in lock['standard_license_texts']['texts'].items():
            if hashlib.sha256(archive.read(item['path'])).hexdigest() != item['sha256']:
                raise ValueError('Missing or changed standard license: ' + identifier)
        for item in components:
            for name in item['notice_files']:
                if name not in notice_names:
                    raise ValueError('Missing dependency license notice: ' + name)

    binary_archive = checked_file(root, descriptor['binaryArchive']['name'], descriptor['binaryArchive']['sha256'])
    binaries = {}
    with zipfile.ZipFile(binary_archive) as archive:
        for tool, expected_hash in descriptor['binaries'].items():
            matches = [name for name in archive.namelist() if name.endswith('/bin/' + tool + '.exe')]
            if len(matches) != 1:
                raise ValueError('Ambiguous upstream binary: ' + tool)
            data = archive.read(matches[0])
            if hashlib.sha256(data).hexdigest() != expected_hash:
                raise ValueError('Binary does not match the reviewed source distribution: ' + tool)
            binaries[tool] = data
    return {'schema': 'jiying.ffmpeg-source-verification/v1', 'ffmpegCommit': lock['ffmpeg_commit'],
            'buildRecipeCommit': lock['build_recipe_commit'], 'dependencySourcesVerified': len(components),
            'inactiveCacheStagesPreservedAsEvidence': descriptor['inactiveCacheStages'],
            'supplementalSourcesVerified': len(supplemental), 'rustRegistryCratesVerified': len(lock['rav1e_registry_crates']),
            'rustStdRegistryCratesVerified': len(lock['rust_std_registry_crates']),
            'licenseNoticeFilesVerified': len(names), 'binaries': descriptor['binaries'],
            'bitForBitRebuildPerformed': False, 'legalOpinion': False, 'limitations': descriptor['limitations']}, binaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sources', type=Path)
    parser.add_argument('--tools-output', type=Path, required=True)
    parser.add_argument('--release-output', type=Path)
    args = parser.parse_args()
    report, binaries = verify(args.sources)
    descriptor = json.loads(DESCRIPTOR.read_text('utf-8'))
    args.tools_output.mkdir(parents=True, exist_ok=False)
    for name, data in binaries.items():
        (args.tools_output / (name + '.exe')).write_bytes(data)
    notice_asset = next(item for item in descriptor['sourceAssets'] if item['name'].endswith('-notices.zip'))
    shutil.copy2(args.sources / notice_asset['name'], args.tools_output / notice_asset['name'])
    (args.tools_output / 'source-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.release_output:
        args.release_output.mkdir(parents=True, exist_ok=True)
        for item in descriptor['sourceAssets']:
            shutil.copy2(args.sources / item['name'], args.release_output / item['name'])
        receipt = {'schema': 'jiying.corresponding-source/v1', 'complete': True,
                   'reviewedBy': 'Codex automated technical content and provenance verification; not a legal opinion',
                   'reviewedAt': datetime.now(timezone.utc).isoformat(), 'binaries': descriptor['binaries'],
                   'assets': descriptor['sourceAssets'], 'verification': report}
        (args.release_output / 'corresponding-source.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
