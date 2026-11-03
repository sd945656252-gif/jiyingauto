'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {verifyRelease}=require('./verify-release.cjs');
const semver=require('semver');

function sha256(file){
  const hash=createHash('sha256'),buffer=Buffer.alloc(1024*1024),fd=fs.openSync(file,'r');
  try {let count;while((count=fs.readSync(fd,buffer,0,buffer.length,null))>0)hash.update(buffer.subarray(0,count));}
  finally {fs.closeSync(fd);}
  return hash.digest('hex');
}
function contained(root,relative) {
  if(typeof relative!=='string'||!relative||path.basename(relative)!==relative||/[\\/]/.test(relative))
    throw new Error('发行材料必须是输出目录中的独立文件名');
  const file=path.join(root,relative);
  if(fs.lstatSync(file).isSymbolicLink()||!fs.statSync(file).isFile())throw new Error('发行材料不能是链接或目录');
  return file;
}
function verifySourcePacket(root,backend) {
  if(!fs.existsSync(path.join(root,'corresponding-source.json')))
    throw new Error('缺少完整对应源码的真实审查回执 corresponding-source.json');
  const receipt=JSON.parse(fs.readFileSync(path.join(root,'corresponding-source.json'),'utf8'));
  if(receipt.schema!=='jiying.corresponding-source/v1'||receipt.complete!==true||
      typeof receipt.reviewedBy!=='string'||!receipt.reviewedBy.trim()||
      !Number.isFinite(Date.parse(receipt.reviewedAt)))throw new Error('完整对应源码尚未审查，不能公开分发');
  for(const name of ['ffmpeg','ffprobe']) {
    if(receipt.binaries?.[name]!==sha256(path.join(backend,'tools',name+'.exe')))
      throw new Error('对应源码审查不属于本次媒体工具二进制');
  }
  const roles=new Set();
  if(!Array.isArray(receipt.assets)||!receipt.assets.length)throw new Error('缺少可同次发布的源码文件');
  const names=new Set();
  const assets=receipt.assets.map(asset=>{
    if(names.has(asset.name))throw new Error('源码材料文件名重复');
    names.add(asset.name);
    if(!Array.isArray(asset.roles)||asset.roles.some(role=>!['ffmpeg','linked-libraries','build-scripts'].includes(role)))
      throw new Error('对应源码材料身份无效');
    asset.roles.forEach(role=>roles.add(role));
    const file=contained(root,asset.name);
    if(fs.statSync(file).size===0||sha256(file)!==asset.sha256)throw new Error('源码材料缺失或哈希不一致');
    return {name:asset.name,sha256:asset.sha256,bytes:fs.statSync(file).size};
  });
  if(!['ffmpeg','linked-libraries','build-scripts'].every(role=>roles.has(role)))
    throw new Error('缺少 FFmpeg、静态依赖或构建脚本的完整对应源码');
  const license=path.join(backend,'licenses/distribution/ffmpeg/GPL-3.0.txt');
  const gpl=fs.readFileSync(license,'utf8');
  if(!gpl.includes('GNU GENERAL PUBLIC LICENSE')||!gpl.includes('END OF TERMS AND CONDITIONS')||gpl.length<30000)
    throw new Error('缺少完整 GPLv3 许可证');
  return {reviewedBy:receipt.reviewedBy,reviewedAt:receipt.reviewedAt,assets};
}
function verifyAuthenticode(installer,application,publisher) {
  if(process.platform!=='win32')throw new Error('签名验证必须在 Windows 上实际执行');
  if(!publisher?.startsWith('CN='))throw new Error('缺少待核验的完整发布者身份 JIYING_SIGN_PUBLISHER');
  const args=['-NoProfile','-NonInteractive','-File',path.join(__dirname,'verify-authenticode.ps1'),
    '-InstallerPath',installer,'-ApplicationPath',application,'-PublisherSubject',publisher];
  let output;
  try {output=execFileSync('powershell.exe',args,{encoding:'utf8',windowsHide:true,timeout:30000});}
  catch(error) {
    try {const result=JSON.parse(String(error.stdout||''));throw new Error('真实签名检查未通过：'+result.signatures.map(row=>row.status).join(' / '));}
    catch(parsed) {if(parsed.message.startsWith('真实签名'))throw parsed;throw new Error('真实签名检查未完成或未通过');}
  }
  const result=JSON.parse(output.replace(/^\uFEFF/,''));
  if(result.valid!==true||!result.sameSigner)throw new Error('签名或发布者验证失败');
  return result;
}
function checkReadiness(directory,version,{publisher=process.env.JIYING_SIGN_PUBLISHER,signatureVerifier=verifyAuthenticode,unsignedPreview=false}={}) {
  const root=path.resolve(directory);
  const blockers=[];
  const warnings=[];
  let packet,source,signatures;
  try {packet=verifyRelease(root,version);} catch(error){blockers.push({check:'packet',message:error.message});}
  const backend=path.join(root,'win-unpacked/resources/backend');
  try {source=verifySourcePacket(root,backend);} catch(error){blockers.push({check:'corresponding-source',message:error.message});}
  if(packet) {
    const installer=packet.assets.find(asset=>asset.name.endsWith('.exe'));
    if(unsignedPreview&&semver.prerelease(version)) {
      signatures={verified:false,policy:'explicit-unsigned-preview'};
      warnings.push({check:'authenticode',message:'按明确选择的未签名预览版发行；未通过发布者签名验证，不进入正式更新通道'});
    } else {
      if(unsignedPreview)blockers.push({check:'signature-policy',message:'仅预发布版本可选择未签名预览策略'});
      try {signatures=signatureVerifier(path.join(root,installer.name),path.join(root,'win-unpacked/极映.exe'),publisher);}
      catch(error){blockers.push({check:'authenticode',message:error.message});}
    }
  }
  return {schema:'jiying.release-readiness/v1',version,ready:blockers.length===0,blockers,warnings,
    packet:packet||null,source:source||null,signatures:signatures||null,
    published:false,scope:'安装包完整性、对应源码审查回执和实际签名；不代替法律审查或真实覆盖升级验收'};
}
if(require.main===module) {
  const directory=path.resolve(process.argv[2]||'../artifacts/desktop-dist');
  const report=checkReadiness(directory,process.argv[3]||require('./package.json').version,{unsignedPreview:process.argv.includes('--unsigned-preview')});
  fs.writeFileSync(path.join(directory,'release-readiness.json'),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify(report,null,2)+'\n');
  if(!report.ready)process.exitCode=1;
}
module.exports={checkReadiness,verifySourcePacket,verifyAuthenticode};
