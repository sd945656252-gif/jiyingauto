"""Deliver verified third-party sources to an existing draft; never publishes it."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request

repo = 'sd945656252-gif/jiyingauto'
version = os.environ['RELEASE_VERSION']
phase = os.environ['VERIFICATION_PHASE']
if not re.fullmatch(r'\d+\.\d+\.\d+-(?:alpha|beta|rc)\.\d+', version) or phase not in ('sources', 'verify-package'):
    raise SystemExit('Only explicit preview versions and known verification phases are accepted')
tag = 'v' + version
tools = Path(__file__).resolve().parent
descriptor = json.loads((tools / 'third-party/ffmpeg/source-distribution.json').read_text('utf-8'))


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


release = json.loads(gh('release', 'view', tag, '--repo', repo, '--json', 'isDraft,isPrerelease'))
if not release['isDraft'] or not release['isPrerelease']:
    raise SystemExit('This job only updates existing prerelease drafts')
downloads = Path('media-source-downloads')
downloads.mkdir(exist_ok=False)
args = ['gh', 'release', 'download', 'ffmpeg-9.0.2-1', '--repo', 'mrkbac/portable-ffmpeg', '--dir', str(downloads)]
for asset in descriptor['sourceAssets']:
    args.extend(['--pattern', asset['name']])
subprocess.run(args, check=True)
lock = json.loads((downloads / descriptor['sourceLock']['name']).read_text('utf-8'))
if digest(downloads / descriptor['sourceLock']['name']) != descriptor['sourceLock']['sha256']:
    raise SystemExit('Changed source lock')
cache = json.loads(gh('api', 'repos/BtbN/FFmpeg-Builds/actions/artifacts/' + str(descriptor['sourceCache']['artifactId'])))
if cache['digest'] != 'sha256:' + descriptor['sourceCache']['sha256'] or cache['workflow_run']['head_sha'] != descriptor['buildRecipeCommit']:
    raise SystemExit('Original build cache provenance does not match')
run = json.loads(gh('api', 'repos/BtbN/FFmpeg-Builds/actions/runs/' + descriptor['buildRun'].rsplit('/', 1)[1]))
if run['head_sha'] != descriptor['buildRecipeCommit'] or run['conclusion'] != 'success':
    raise SystemExit('Original build was not successful at the pinned commit')
for item in lock['supplemental_sources']:
    if any(key in item['arcname'] for key in ('/ffmpeg-', '/btbn-build-recipes-')):
        target = downloads / ('official-' + item['arcname'].rsplit('/', 1)[1])
        urllib.request.urlretrieve(item['url'], target)
        if digest(target) != item['sha256']:
            raise SystemExit('Supplemental source does not match the original repository archive')
binary = descriptor['binaryArchive']
urllib.request.urlretrieve(binary['url'], downloads / binary['name'])
subprocess.run(['python3', str(tools / 'verify_ffmpeg_sources.py'), str(downloads),
                '--tools-output', 'media-tools', '--release-output', 'packet'], check=True)
packet = Path('packet')
shutil.copy2('media-tools/source-verification.json', packet / 'source-verification.json')
report = {'schema': 'jiying.source-actions-evidence/v1', 'repository': repo,
          'workflowCommit': os.environ['GITHUB_SHA'],
          'workflowRun': os.environ['GITHUB_SERVER_URL'] + '/' + repo + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
          'phase': phase, 'originalBuildCommit': run['head_sha'], 'originalSourceCacheDigest': cache['digest'],
          'sourceVerificationSha256': digest(packet / 'source-verification.json'),
          'verifierSha256': digest(tools / 'verify_ffmpeg_sources.py'), 'published': False}
if phase == 'verify-package':
    args = ['gh', 'release', 'download', tag, '--repo', repo, '--dir', str(packet)]
    for name in ['jiying-desktop-setup-' + version + '.exe', 'jiying-desktop-setup-' + version + '.exe.blockmap', 'latest.yml', 'build-verification.json']:
        args.extend(['--pattern', name])
    subprocess.run(args, check=True)
    installer = packet / ('jiying-desktop-setup-' + version + '.exe')
    subprocess.run(['7z', 'x', '-y', '-bd', str(installer), '-oinstaller-unpacked'], check=True, stdout=subprocess.DEVNULL)
    archives = list(Path('installer-unpacked').rglob('app-64.7z'))
    if len(archives) != 1:
        raise SystemExit('Cannot locate the actual installer application payload')
    subprocess.run(['7z', 'x', '-y', '-bd', str(archives[0]), '-oinstaller-application',
                    'resources/backend/tools/*', 'resources/backend/licenses/distribution/ffmpeg/*'],
                   check=True, stdout=subprocess.DEVNULL)
    backend = packet / 'win-unpacked/resources/backend'
    backend.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree('installer-application/resources/backend', backend)
    for name, expected in descriptor['binaries'].items():
        if digest(backend / 'tools' / (name + '.exe')) != expected:
            raise SystemExit('Installer still contains an unreviewed media binary')
    subprocess.run(['node', str(tools / 'verify-release.cjs'), str(packet), version], check=True)
    subprocess.run(['node', str(tools / 'release-readiness.cjs'), str(packet), version, '--unsigned-preview'], check=True)
    report['installerSha256'] = digest(installer)
    report['actualInstallerMediaBinariesMatched'] = True
    report['unsignedPreviewReadinessPassed'] = True
(packet / 'source-actions-evidence.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
assets = [packet / item['name'] for item in descriptor['sourceAssets']]
assets.extend(packet / name for name in ['corresponding-source.json', 'source-verification.json', 'source-actions-evidence.json'])
if phase == 'verify-package':
    assets.extend(packet / name for name in ['release-validation.json', 'release-readiness.json'])
subprocess.run(['gh', 'release', 'upload', tag, '--repo', repo, '--clobber', *map(str, assets)], check=True)
print(json.dumps(report, indent=2))
