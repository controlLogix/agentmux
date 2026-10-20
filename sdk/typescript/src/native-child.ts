/** Pinned native child transport. No discovery, reconnect or business authority. */
import {createHash, createPrivateKey, sign} from 'node:crypto';
import {constants, openSync, closeSync, fstatSync, readSync, lstatSync, realpathSync} from 'node:fs';
import {isAbsolute, normalize, resolve} from 'node:path';
import {connect as tlsConnect, TLSSocket} from 'node:tls';
import {ContractError, strictLoads, validate, canonicalBytes} from './index.js';

function fail():never {throw new ContractError('native_child_invalid');}
function freeze<T>(value:T):T {if(value && typeof value==='object'){for(const v of Object.values(value))freeze(v);Object.freeze(value);}return value;}
function digest(raw:Uint8Array):string{return 'sha256:'+createHash('sha256').update(raw).digest('hex');}
function privateFile(path:string):Buffer {
  if(typeof path!=='string'||!isAbsolute(path)||normalize(path)!==path||path.startsWith('//')||realpathSync(path)!==path)fail();
  const directories:{path:string;fd:number}[]=[];let fd:number|undefined;
  try {
    let prefix='';
    for(const part of path.slice(1).split('/').slice(0,-1)){
      prefix+='/'+part;directories.push({path:prefix,fd:openSync(prefix,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW)});
    }
    const parent=fstatSync(directories.at(-1)!.fd);
    if(parent.uid!==process.geteuid!()||(parent.mode&0o777)!==0o700)fail();
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const before=fstatSync(fd,{bigint:true});
    if(!before.isFile()||before.uid!==BigInt(process.geteuid!())||before.nlink!==1n||(before.mode&0o777n)!==0o600n||before.size>1048576n)fail();
    const storage=Buffer.alloc(1048577),size=readSync(fd,storage,0,storage.length,null),raw=storage.subarray(0,size),after=fstatSync(fd,{bigint:true});
    if(BigInt(raw.length)!==before.size||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs)fail();
    for(const dir of directories){const original=fstatSync(dir.fd),current=lstatSync(dir.path);if(!current.isDirectory()||original.dev!==current.dev||original.ino!==current.ino)fail();}
    const current=lstatSync(path,{bigint:true});if(current.dev!==before.dev||current.ino!==before.ino)fail();
    return raw;
  }finally{if(fd!==undefined)closeSync(fd);for(const dir of directories.reverse())closeSync(dir.fd);}
}
function trust(t:any):number {
  if(typeof t.serverURL!=='string'||typeof t.serverName!=='string'||typeof t.leafCertificateSha256!=='string')fail();
  const match=/^tls:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(t.serverURL),name=t.serverName;
  if(!match||Number(match[1])>65535||!/^sha256:[0-9a-f]{64}$/.test(t.leafCertificateSha256)||!name||name.length>253||/^[0-9.]+$/.test(name)||!name.split('.').every((v:string)=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v)))fail();
  return Number(match[1]);
}
function keys(value:any,required:string[],optional:string[]=[]):void {
  if(!value||Array.isArray(value)||typeof value!=='object'||required.some(k=>!Object.hasOwn(value,k))||Object.keys(value).some(k=>![...required,...optional].includes(k)))fail();
}
function deadline(value:unknown):number {
  if(typeof value!=='string')fail();
  const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value);
  if(!match)fail();const calendar=Date.parse(match[1]+'Z'),actual=Date.parse(value);
  if(!Number.isFinite(calendar)||!Number.isFinite(actual)||new Date(calendar).toISOString().slice(0,19)!==match[1])fail();
  return actual;
}
function credentials(raw:Buffer):{jwt:string;seed:Buffer}{
  const text=raw.toString('ascii'),jwt=[...text.matchAll(/-----BEGIN NATS USER JWT-----\s+([A-Za-z0-9_.-]+)\s+------END NATS USER JWT------/g)],seeds=[...text.matchAll(/-----BEGIN USER NKEY SEED-----\s+([A-Z2-7]+)\s+------END USER NKEY SEED------/g)];
  if(jwt.length!==1||seeds.length!==1)fail();
  let acc=0,bits=0;const bytes:number[]=[];
  for(const ch of seeds[0][1]){acc=(acc<<5)|'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);bits+=5;if(bits>=8){bits-=8;bytes.push((acc>>>bits)&255);}}
  const data=Buffer.from(bytes);let crc=0;
  for(const byte of data.subarray(0,-2)){crc^=byte<<8;for(let i=0;i<8;i++)crc=((crc<<1)^((crc&0x8000)?0x1021:0))&0xffff;}
  if(data.length!==36||(data[0]&248)!==144||(((data[0]&7)<<5)|(data[1]>>>3))!==160||data.readUInt16LE(34)!==crc)fail();
  return {jwt:jwt[0][1],seed:Buffer.from(data.subarray(2,34))};
}
export class NativeChildBootstrap {
  constructor(readonly document:any,private readonly config:Buffer,readonly context:any,private readonly resources:Map<string,Buffer>,private readonly schemaDir:string){freeze(document);freeze(context);}
  resource(path:string):Buffer{const value=this.resources.get(path);if(!value)fail();return Buffer.from(value);}
  validateControl(value:unknown):void{validate('ordinary-plugin-lifecycle',value,this.schemaDir);}
  get configuration():Buffer{return Buffer.from(this.config);}
  toJSON():object{return {kind:'native-child-bootstrap'};}
  [Symbol.for('nodejs.util.inspect.custom')]():string{return '[NativeChildBootstrap private]';}
}
export function loadNativeBootstrap(path:string,schemaDir?:string):NativeChildBootstrap {
  try {
    schemaDir=resolve(schemaDir??process.env.AGENTMUX_SCHEMA_DIR??'contracts/v1/schemas');
    const d:any=strictLoads(privateFile(path));
    keys(d,['schemaVersion','serverURL','caFile','credentialsFile','configurationFile','controlSubject','eventSubject','prepare','serverName','leafCertificateSha256'],['context']);
    validate('ordinary-plugin-lifecycle',d.prepare,schemaDir);
    if(d.prepare.kind!=='ordinary-plugin-control'||d.prepare.action!=='prepare'||d.schemaVersion!==d.prepare.schemaVersion)fail();
    deadline(d.prepare.deadline);trust(d);const instance=d.prepare.owner.instanceId;
    if(typeof d.controlSubject!=='string'||d.controlSubject.split('.').length!==8)fail();
    const parts=d.controlSubject.split('.');
    if(parts.slice(0,3).join('.')!=='amx.v1.h'||!/^[a-z][a-z0-9_-]{0,95}$/.test(parts[3])||parts[4]!=='plugins'||parts[5]!==instance||parts.slice(6).join('.')!=='lifecycle.control')fail();
    if(d.eventSubject!==d.controlSubject.slice(0,-7)+'event')fail();
    const config=privateFile(d.configurationFile);if(digest(config)!==d.prepare.configurationChecksum)fail();
    let descriptor:any=null;
    if(d.context!==undefined){
      const c=d.context;keys(c,['contextFile','credentialsFile','caFile','transport']);const t=c.transport;
      keys(t,['schemaVersion','serverURL','serverName','leafCertificateSha256','requestSubject','replySubject','invokeSubject','resultSubject','cancelSubject']);
      if(t.schemaVersion!=='1.0.0')fail();trust(t);
      const prefix=d.controlSubject.slice(0,-'lifecycle.control'.length);
      for(const [key,suffix] of Object.entries({requestSubject:'context.request',replySubject:'context.reply',invokeSubject:'operation.invoke',resultSubject:'operation.result',cancelSubject:'operation.cancel'}))if(t[key]!==prefix+suffix)fail();
      const raw=privateFile(c.contextFile);if(digest(raw)!==d.prepare.contextChecksum)fail();descriptor=strictLoads(raw);
      validate('plugin-context',descriptor,schemaDir);
      if(descriptor.instanceId!==instance||descriptor.hubId!==parts[3]||descriptor.packageId!==d.prepare.owner.pin.packageId||descriptor.packageVersion!==d.prepare.owner.pin.version||descriptor.packageDigest!==d.prepare.owner.pin.packageChecksum)fail();
    }else if(d.prepare.schemaVersion==='1.2.0')fail();
    const resources=new Map<string,Buffer>();
    for(const path of [d.caFile,d.credentialsFile,...(d.context?[d.context.caFile,d.context.credentialsFile]:[])])if(!resources.has(path))resources.set(path,privateFile(path));
    return new NativeChildBootstrap(d,config,descriptor,resources,schemaDir);
  }catch{throw new ContractError('native_child_invalid');}
}

class Connection {
  private buffer=Buffer.alloc(0);private pending:{subject:string;size:number}|undefined;
  private readonly queues=new Map<string,Buffer[]>();private readonly waiters=new Map<string,((raw:Buffer|undefined)=>void)[]>();
  private pongs:(()=>void)[]=[];private ended=false;private flushTail:Promise<void>=Promise.resolve();
  private readonly joined:Promise<void>;
  constructor(readonly socket:TLSSocket,private readonly publishSubjects:ReadonlySet<string>,private readonly subjects:string[]){
    for(const subject of subjects){this.queues.set(subject,[]);this.waiters.set(subject,[]);}
    this.joined=new Promise(resolve=>{socket.once('close',()=>{this.end();resolve();});});
    socket.on('error',()=>this.end());socket.on('data',raw=>{try{this.read(raw);}catch{this.end();socket.destroy();}});
  }
  private end():void{this.ended=true;for(const pending of this.waiters.values())for(const resolve of pending.splice(0))resolve(undefined);for(const resolve of this.pongs.splice(0))resolve();}
  private read(raw:Buffer):void {
    this.buffer=Buffer.concat([this.buffer,raw]);if(this.buffer.length>1114112)fail();
    while(true){
      if(this.pending){const {subject,size}=this.pending;if(this.buffer.length<size+2)return;if(this.buffer.subarray(size,size+2).toString()!=='\r\n')fail();
        const payload=Buffer.from(this.buffer.subarray(0,size));this.buffer=this.buffer.subarray(size+2);this.pending=undefined;
        const waiter=this.waiters.get(subject)!.shift();if(waiter)waiter(payload);else {const queue=this.queues.get(subject)!;if(queue.length>=64)fail();queue.push(payload);}continue;
      }
      const end=this.buffer.indexOf('\r\n');if(end<0){if(this.buffer.length>65536)fail();return;}
      if(end>65536)fail();const line=this.buffer.subarray(0,end).toString('ascii');this.buffer=this.buffer.subarray(end+2);
      if(line==='PING')this.socket.write('PONG\r\n');
      else if(line==='PONG')this.pongs.shift()?.();
      else if(line.startsWith('MSG ')){
        const fields=line.split(' '),sid=Number(fields[2]),size=Number(fields[3]);
        if(fields.length!==4||!Number.isSafeInteger(sid)||sid<1||sid>this.subjects.length||fields[1]!==this.subjects[sid-1]||!/^\d+$/.test(fields[3])||size>1048576)fail();this.pending={subject:fields[1],size};
      }else if(!line.startsWith('INFO ')&&line!=='+OK')fail();
    }
  }
  async flush():Promise<void>{
    const next=this.flushTail.then(()=>new Promise<void>((resolve,reject)=>{
      if(this.ended){reject(new ContractError('native_child_connection_failed'));return;}
      const timer=setTimeout(()=>{this.socket.destroy();reject(new ContractError('native_child_connection_failed'));},2000);
      this.pongs.push(()=>{clearTimeout(timer);this.ended?reject(new ContractError('native_child_connection_failed')):resolve();});this.socket.write('PING\r\n');
    }));this.flushTail=next.catch(()=>{});return next;
  }
  async publish(subject:string,raw:Uint8Array):Promise<void>{
    if(!this.publishSubjects.has(subject)||!(raw instanceof Uint8Array)||raw.byteLength>1048576||this.ended)fail();
    await new Promise<void>((resolve,reject)=>this.socket.write(Buffer.concat([Buffer.from(`PUB ${subject} ${raw.byteLength}\r\n`),raw,Buffer.from('\r\n')]),error=>error?reject(new ContractError('native_child_connection_failed')):resolve()));
  }
  async receive(subject:string):Promise<Buffer>{
    if(!this.queues.has(subject)||this.ended)fail();const queued=this.queues.get(subject)!.shift();if(queued)return queued;
    return new Promise((resolve,reject)=>this.waiters.get(subject)!.push(raw=>raw===undefined?reject(new ContractError('native_child_connection_failed')):resolve(raw)));
  }
  async close():Promise<void>{this.end();this.socket.destroy();await this.joined;await this.flushTail;}
  [Symbol.for('nodejs.util.inspect.custom')]():string{return '[NativeChildConnection private]';}
}
async function connect(t:any,ca:Buffer,credentialRaw:Buffer,publish:string[],subscribe:string[]):Promise<Connection>{
  const port=trust(t),auth=credentials(credentialRaw);
  if((ca.toString('ascii').match(/-----BEGIN CERTIFICATE-----/g)||[]).length!==1)fail();
  let socket:TLSSocket|undefined,connection:Connection|undefined;
  try {
    socket=tlsConnect({host:'127.0.0.1',port,servername:t.serverName,ca,minVersion:'TLSv1.3',rejectUnauthorized:true});
    const sock=socket;
    const initial=await new Promise<Buffer>((resolve,reject)=>{
      let buffer=Buffer.alloc(0);const timer=setTimeout(()=>{sock.destroy();reject(new ContractError('native_child_connection_failed'));},2000);
      const error=()=>{clearTimeout(timer);reject(new ContractError('native_child_connection_failed'));};
      sock.once('error',error);sock.once('close',error);
      sock.once('secureConnect',()=>{
        if(!sock.authorized||sock.getProtocol()!=='TLSv1.3'||digest(sock.getPeerCertificate().raw)!==t.leafCertificateSha256){sock.destroy();return;}
        const read=(raw:Buffer)=>{buffer=Buffer.concat([buffer,raw]);if(buffer.length>65536){sock.destroy();return;}const end=buffer.indexOf('\r\n');if(end>=0){clearTimeout(timer);sock.off('data',read);sock.off('error',error);sock.off('close',error);sock.pause();resolve(buffer);}};
        sock.on('data',read);
      });
    });
    const end=initial.indexOf('\r\n');if(initial.subarray(0,5).toString()!=='INFO ')fail();
    const info:any=strictLoads(initial.subarray(5,end));if(typeof info.nonce!=='string'||!info.nonce||info.nonce.length>1024)fail();
    const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),auth.seed]),type:'pkcs8',format:'der'});
    const sig=sign(null,Buffer.from(info.nonce),key).toString('base64url');auth.seed.fill(0);
    connection=new Connection(sock,new Set(publish),subscribe);
    sock.write('CONNECT '+JSON.stringify({jwt:auth.jwt,sig,verbose:false,pedantic:true,echo:false,protocol:1})+'\r\n');
    subscribe.forEach((subject,index)=>sock.write(`SUB ${subject} ${index+1}\r\n`));
    if(initial.length>end+2)sock.unshift(initial.subarray(end+2));sock.resume();await connection.flush();return connection;
  }catch{if(connection)await connection.close();else if(socket){await new Promise<void>(resolve=>{if(socket!.closed)resolve();else {socket!.once('close',()=>resolve());socket!.destroy();}});}throw new ContractError('native_child_connection_failed');}
}
export class NativeChild {
  lifecycle:Connection|undefined;contextConnection:Connection|undefined;private prepared=false;private control:any;private opening:Promise<this>|undefined;private closing=false;private seenCommands:Set<string>;private stopping=false;
  constructor(readonly bootstrap:NativeChildBootstrap){if(!(bootstrap instanceof NativeChildBootstrap))fail();this.control=bootstrap.document.prepare;this.seenCommands=new Set([this.control.commandId]);}
  async connect():Promise<this>{
    if(this.lifecycle||this.opening||this.closing)fail();
    this.opening=this.open();try{return await this.opening;}finally{this.opening=undefined;}
  }
  private async open():Promise<this>{
    const d=this.bootstrap.document;
    try{
      this.lifecycle=await connect(d,this.bootstrap.resource(d.caFile),this.bootstrap.resource(d.credentialsFile),[d.eventSubject],[d.controlSubject]);
      if(this.closing)fail();
      if(d.context){const c=d.context,t=c.transport;this.contextConnection=await connect(t,this.bootstrap.resource(c.caFile),this.bootstrap.resource(c.credentialsFile),[t.requestSubject,t.resultSubject],[t.replySubject,t.invokeSubject,t.cancelSubject]);}
      if(this.closing)fail();
      await this.report('registered');return this;
    }catch{await this.closeConnections();throw new ContractError('native_child_connection_failed');}
  }
  async nextControl():Promise<any>{
    const d=this.bootstrap.document,control:any=strictLoads(await this.lifecycle!.receive(d.controlSubject));this.bootstrap.validateControl(control);
    if(this.stopping&&control.action!=='stop')fail();
    const expected={...d.prepare};if(control.action==='stop'){if(this.seenCommands.has(control.commandId)||this.seenCommands.size>=64)fail();expected.action='stop';expected.deadline=control.deadline;expected.commandId=control.commandId;}
    if(!canonicalBytes(control).equals(canonicalBytes(expected))||deadline(control.deadline)<Date.now())fail();
    if(control.action==='prepare')this.prepared=true;else {this.seenCommands.add(control.commandId);this.stopping=true;}this.control=control;return freeze(control);
  }
  async report(status:'registered'|'ready'|'failed'|'stopped'):Promise<void>{
    if(!['registered','ready','failed','stopped'].includes(status))fail();
    if((status==='ready'&&(!this.prepared||this.control.action!=='prepare'))||(status==='stopped'&&this.control.action!=='stop'))fail();const {action,deadline,...identity}=this.control;
    const report={...identity,kind:'ordinary-plugin-report',status,observedAt:new Date().toISOString()};
    await this.lifecycle!.publish(this.bootstrap.document.eventSubject,Buffer.from(JSON.stringify(report)));await this.lifecycle!.flush();
  }
  async close():Promise<void>{this.closing=true;if(this.opening)await this.opening.catch(()=>{});await this.closeConnections();}
  private async closeConnections():Promise<void>{const results=await Promise.allSettled([this.contextConnection?.close(),this.lifecycle?.close()]);if(results.some(r=>r.status==='rejected'))throw new ContractError('native_child_cleanup_failed');}
  [Symbol.for('nodejs.util.inspect.custom')]():string{return '[NativeChild private]';}
}
