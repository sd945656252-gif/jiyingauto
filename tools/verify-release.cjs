'use strict';
// Validates a local release packet only; never uploads or creates a release.
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const semver=require('semver');
const YAML=require('yaml');

function verifyRelease(directory,expectedVersion) {
  if(!semver.valid(expectedVersion))throw new Error('发布版本号无效');
  // GitHub release selection uses tag/prerelease metadata. The builder emits
  // latest.yml inside EACH release, including internal prerelease packets.
  const prerelease=semver.prerelease(expectedVersion),channel='latest';
  const root=path.resolve(directory),filename=path.join(root,channel+'.yml');
  const info=YAML.parse(fs.readFileSync(filename,'utf8'));
  if(info.version!==expectedVersion)throw new Error('更新清单版本和软件版本不一致');
  if(!Array.isArray(info.files)||info.files.length!==1)throw new Error('Windows x64 更新清单必须包含一个安装包');
  const row=info.files[0],name=decodeURIComponent(row.url);
  if(path.basename(name)!==name||/[\\/]/.test(name)||!name.endsWith('.exe'))throw new Error('更新安装包路径无效');
  const installer=path.join(root,name),bytes=fs.readFileSync(installer);
  if(row.size!==bytes.length||createHash('sha512').update(bytes).digest('base64')!==row.sha512)throw new Error('安装包大小或SHA512不匹配');
  const blockmap=installer+'.blockmap';if(!fs.statSync(blockmap).isFile()||fs.statSync(blockmap).size===0)throw new Error('缺少差分文件');
  return {schema:'jiying.release-packet/v1',version:expectedVersion,channel,
    stable:!prerelease,assets:[filename,installer,blockmap].map(file=>({name:path.basename(file),bytes:fs.statSync(file).size,
      sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex')})),
    published:false,message:prerelease?'预览版仅用于内部测试；正式版更新通道不会接收此版本':'发布时将三个文件一起上传到同版本 GitHub Release'};
}
if(require.main===module){
  const value=verifyRelease(process.argv[2],process.argv[3]||require('./package.json').version);
  fs.writeFileSync(path.join(path.resolve(process.argv[2]),'release-validation.json'),JSON.stringify(value,null,2));
  process.stdout.write(JSON.stringify(value,null,2)+'\n');
}
module.exports={verifyRelease};
