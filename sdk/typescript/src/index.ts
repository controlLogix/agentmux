import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {readFileSync, readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {visit} from 'jsonc-parser';
import canonicalize from 'canonicalize';
import {Ajv2020} from 'ajv/dist/2020.js';
export {evaluateTransition} from './state-models.js';

export class ContractError extends Error {
  constructor(public readonly code: string) { super(code); }
}
function fail(code: string): never { throw new ContractError(code); }

// JSON values must not invoke user-defined serializers or lose invalid Unicode.
function checkValue(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('invalid_value'); return; }
  if (typeof value === 'string') {
    for (let i=0;i<value.length;i++) {
      const c=value.charCodeAt(i);
      if (c>=0xd800 && c<=0xdbff) {
        const next=value.charCodeAt(++i);
        if (!(next>=0xdc00 && next<=0xdfff)) fail('invalid_value');
      } else if (c>=0xdc00 && c<=0xdfff) fail('invalid_value');
    }
    return;
  }
  if (typeof value !== 'object' || ancestors.has(value)) fail('invalid_value');
  if(ancestors.size>=64) fail('invalid_value');
  if (!Array.isArray(value) && Object.getPrototypeOf(value)!==Object.prototype && Object.getPrototypeOf(value)!==null) fail('invalid_value');
  ancestors.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') fail('invalid_value');
    if (Array.isArray(value) && key==='length') continue;
    const d=Object.getOwnPropertyDescriptor(value,key)!;
    if (!d.enumerable || !('value' in d)) fail('invalid_value');
    checkValue(key,ancestors); checkValue(d.value,ancestors);
  }
  if (Array.isArray(value) && (Object.keys(value).length!==value.length || Object.keys(value).some((k,i)=>k!==String(i)))) fail('invalid_value');
  ancestors.delete(value);
}

export function strictLoads(raw: string | Uint8Array): unknown {
  if((typeof raw==='string'?Buffer.byteLength(raw,'utf8'):raw.byteLength)>1048576) fail('invalid_json');
  let text: string;
  try { text=typeof raw==='string' ? raw : new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw); }
  catch { return fail('invalid_json'); }
  const stack: Set<string>[]=[];
  let invalid=false;
  let depth=0;
  visit(text,{
    onObjectBegin:()=>{if(++depth>64)fail('invalid_json');stack.push(new Set());},
    onObjectProperty:(key)=>{const keys=stack.at(-1)!; if(keys.has(key)) invalid=true; keys.add(key);},
    onObjectEnd:()=>{stack.pop();depth--;},
    onArrayBegin:()=>{if(++depth>64)fail('invalid_json');},
    onArrayEnd:()=>{depth--;},
    onLiteralValue:(_v,offset,length)=>{const token=text.slice(offset,offset+length);if(/^-?\d+$/.test(token) && (BigInt(token)>9007199254740991n || BigInt(token)<-9007199254740991n)) invalid=true;},
    onError:()=>{invalid=true;}
  },{disallowComments:true,allowTrailingComma:false,allowEmptyContent:false});
  if(invalid) fail('invalid_json');
  let value:unknown;
  try { value=JSON.parse(text); } catch { return fail('invalid_json'); }
  checkValue(value); return value;
}

export function canonicalBytes(value:unknown):Buffer {
  checkValue(value);
  const text=canonicalize(value);
  if(text===undefined) fail('invalid_value');
  if(Buffer.byteLength(text,'utf8')>1048576) fail('invalid_value');
  return Buffer.from(text,'utf8');
}
export function payloadDigest(value:unknown):string {return 'sha256:'+createHash('sha256').update(canonicalBytes(value)).digest('hex');}
// Keep one compiled bundle. Every call checks trusted on-disk bytes before reuse.
let compiledBundle: {fingerprint:string; ajv:Ajv2020} | undefined;
export function validate(schemaName:string,value:unknown,schemaDir=process.env.AGENTMUX_SCHEMA_DIR ?? resolve('contracts/v1/schemas')):true {
  checkValue(value);
  if(!/^[a-z][a-z-]*$/.test(schemaName)) fail('invalid_schema');
  const root=resolve(schemaDir);
  const files=readdirSync(root).filter(f=>f.endsWith('.schema.json')).sort().map(name=>({name,bytes:readFileSync(resolve(root,name))}));
  const hash=createHash('sha256').update(JSON.stringify(root));
  for(const file of files)hash.update(JSON.stringify([file.name,file.bytes.length])).update(file.bytes);
  const fingerprint=hash.digest('hex');
  if(compiledBundle?.fingerprint!==fingerprint){
    const ajv=new Ajv2020({strict:false,allErrors:true,validateFormats:false});
    for(const file of files)ajv.addSchema(strictLoads(file.bytes) as object);
    compiledBundle={fingerprint,ajv};
  }
  const ajv=compiledBundle.ajv;
  const validator=ajv.getSchema('urn:agentmux:contract:1:'+schemaName);
  if(!validator || !validator(value)) fail('invalid_schema');
  semanticCheck(schemaName,value);
  return true;
}
// Local cross-field invariants only; these do not authenticate grants or owners.
function semanticCheck(name:string,v:any):void {
  const require=(condition:boolean)=>{if(!condition)fail('invalid_semantics');};
  const distinct=(values:string[])=>new Set(values).size===values.length;
  if(name==='protected-assembly')require(v.plugins.length===4 && distinct(v.plugins.map((p:any)=>p.id)) && v.plugins.every((p:any)=>['boot','kernel-lifecycle','internal-communication','exported-status'].includes(p.id)));
  if(name==='plugin-manifest'){
    for(const [collection,key] of [['dependencies','packageId'],['children','packageId'],['contributions','id']])require(distinct(v[collection].map((item:any)=>item[key])));
    require([...v.dependencies,...v.children].every((d:any)=>d.packageId!==v.packageId));
    for(const c of v.requestedCapabilities)require(!c.resourceClass.startsWith('kernel') || (c.resourceClass==='kernel-status' && c.action==='subscribe'));
    for(const d of v.dependencies){
      const low=d.minimumVersion.split('.').map(BigInt),high=d.exclusiveMaximumVersion.split('.').map(BigInt);
      let cmp=0;for(let i=0;i<3 && cmp===0;i++)cmp=low[i]<high[i]?-1:low[i]>high[i]?1:0;
      require(cmp<0);
    }
  }
  if(name==='plugin-context'){
    const g=v.effectiveGrant;
    require(!v.parent || v.parent.instanceId!==v.instanceId);
    require(!v.parent || v.parent.relationship!=='private' || g.parentGrantRef!==null);
    require(g.subjectInstanceId===v.instanceId);
    require(instant(g.issuedAt)<instant(g.expiresAt));
  }
  if(['message-envelope','owner-record'].includes(name))semanticCheck('operation-context',v.operation);
  if(name==='operation-context')instant(v.deadline);
  if(name==='owner-record'){
    require(distinct(v.effects.map((e:any)=>e.effectId)));
    require(v.outcome!=='rejected' || v.effects.length===0);
  }
  if(name==='ingress-attestation'){
    const c=v.claims;semanticCheck('operation-context',c.operation);
    require(c.signingKeyRef.ownerHubId===c.issuerHubId && c.authenticatedTransportRef.ownerHubId===c.issuerHubId);
    require(instant(c.issuedAt)<instant(c.expiresAt) && instant(c.expiresAt)<=instant(c.operation.deadline));
    instant(c.sentAt);
  }
  if(name==='message-envelope'){
    semanticCheck('ingress-attestation',v.ingressAttestation);
    const c=v.ingressAttestation.claims;
    for(const key of ['operation','messageId','kind','contractId','contractMajor','sourceHubId','sourceInstanceId','sentAt','correlationId'])require(canonicalBytes(c[key]).equals(canonicalBytes(v[key])));
    require(c.audience.hubId===v.destinationHubId && c.audience.serviceId===v.destinationServiceId);
  }
}
function privateKey(seed:Uint8Array) {
  if(seed.length!==32) fail('invalid_key');
  return createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
}
export function signClaims(claims:unknown,seed32:Uint8Array):string {return sign(null,canonicalBytes(claims),privateKey(seed32)).toString('base64url');}
export function publicKeyForSeed(seed32:Uint8Array):Buffer {return createPublicKey(privateKey(seed32)).export({format:'der',type:'spki'}).subarray(-32);}

function instant(value:unknown):bigint {
  if(typeof value!=='string') fail('invalid_time');
  const m=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z$/.exec(value);
  if(!m || m[1].startsWith('0000-')) fail('invalid_time');
  const ms=Date.parse(m[1]+'Z');
  if(!Number.isFinite(ms) || new Date(ms).toISOString().slice(0,19)!==m[1]) fail('invalid_time');
  return BigInt(ms)*1000n+BigInt((m[2]??'').padEnd(6,'0'));
}
export function verifyAttestation(attestation:any,publicKey32:Uint8Array,expectedAudience:{hubId:string;serviceId:string},now:string,payload:unknown):any {
  validate('ingress-attestation',attestation);
  if(publicKey32.length!==32) fail('invalid_key');
  const c=attestation.claims;
  const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),publicKey32]),format:'der',type:'spki'});
  if(!verify(null,canonicalBytes(c),key,Buffer.from(attestation.signature,'base64url'))) fail('invalid_signature');
  if(c.audience.hubId!==expectedAudience.hubId || c.audience.serviceId!==expectedAudience.serviceId) fail('invalid_audience');
  if(c.issuerHubId!==c.signingKeyRef.ownerHubId || c.issuerHubId!==c.authenticatedTransportRef.ownerHubId) fail('invalid_binding');
  const t=instant(now), issued=instant(c.issuedAt),expires=instant(c.expiresAt),deadline=instant(c.operation.deadline),sent=instant(c.sentAt);
  if(issued>t || t>=expires || t>=deadline || issued>=expires || expires>deadline || sent>t) fail('invalid_time');
  if(c.operation.payloadDigest!==payloadDigest(payload)) fail('invalid_payload');
  return c;
}

export function verifyEnvelope(envelope:any,publicKey32:Uint8Array,expectedAudience:{hubId:string;serviceId:string},now:string):any {
  validate('message-envelope',envelope);
  const c=verifyAttestation(envelope.ingressAttestation,publicKey32,expectedAudience,now,envelope.payload);
  for(const field of ['operation','messageId','kind','contractId','contractMajor','sourceHubId','sourceInstanceId','sentAt','correlationId']) {
    if(!canonicalBytes(envelope[field]).equals(canonicalBytes(c[field]))) fail('invalid_binding');
  }
  if(envelope.destinationHubId!==c.audience.hubId || envelope.destinationServiceId!==c.audience.serviceId) fail('invalid_binding');
  validatePayload(envelope);
  return c;
}


export function validatePayload(envelope:any,registryPath=resolve(process.env.AGENTMUX_SCHEMA_DIR ?? 'contracts/v1/schemas','../registry.json')):true {
  validate('message-envelope',envelope);
  const registry=strictLoads(readFileSync(registryPath)) as any;
  if(registry.schemaVersion!=='1.0.0')fail('invalid_registry');
  const entry=Object.hasOwn(registry.contracts,envelope.contractId)?registry.contracts[envelope.contractId]:undefined;
  if(!entry || entry.major!==envelope.contractMajor)fail('unknown_contract');
  if(entry.kind!==envelope.kind)fail('invalid_kind');
  if(entry.destinationServiceId!==null && entry.destinationServiceId!==envelope.destinationServiceId)fail('invalid_destination');
  validate(entry.payloadSchema,envelope.payload,resolve(registryPath,'../schemas'));
  const p=envelope.payload,o=envelope.operation;
  for(const field of ['taskId','attemptId'])if(p[field]!=null && p[field]!==o[field])fail('invalid_payload_context');
  if(p.delegationId!=null && (!o.delegationRef || p.delegationId!==o.delegationRef.id))fail('invalid_payload_context');
  if(envelope.contractId==='operation-outcome' && p.operationId!==envelope.correlationId)fail('invalid_payload_context');
  return true;
}

export {NativeChild, NativeChildBootstrap, loadNativeBootstrap} from './native-child.js';
