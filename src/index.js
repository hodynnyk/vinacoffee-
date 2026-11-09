const headers={'cache-control':'no-store','x-content-type-options':'nosniff'};
const reply=(body,status=200,extra={})=>Response.json(body,{status,headers:{...headers,...extra}});
const enc=new TextEncoder();
const hex=bytes=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
async function sha(value){return hex(await crypto.subtle.digest('SHA-256',enc.encode(value)))}
async function passwordHash(password,salt=crypto.getRandomValues(new Uint8Array(16))){const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);const bytes=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},key,256);return 'pbkdf2-sha256:100000:'+hex(salt)+':'+hex(bytes)}
async function checkPassword(password,stored){const parts=stored.split(':');if(parts.length!==4||parts[0]!=='pbkdf2-sha256'||parts[1]!=='100000'||!/^[a-f0-9]{32}$/.test(parts[2]))return false;const salt=new Uint8Array(parts[2].match(/../g).map(x=>parseInt(x,16)));const candidate=await passwordHash(password,salt);const a=enc.encode(candidate),b=enc.encode(stored);let diff=a.length^b.length;for(let i=0;i<Math.min(a.length,b.length);i++)diff|=a[i]^b[i];return diff===0}
const cookie=request=>(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('vina_session='))?.slice(13);
async function session(request,env){const token=cookie(request);if(!token)return null;const hash=await sha(token);return env.DB.prepare("SELECT employees.id,employees.display_name,employees.role FROM sessions JOIN employees ON employees.id=sessions.employee_id WHERE sessions.id_hash=? AND sessions.revoked_at IS NULL AND sessions.expires_at > ? AND employees.active=1").bind(hash,new Date().toISOString()).first()}
function sameOrigin(request){const origin=request.headers.get('origin');return origin===new URL(request.url).origin}
async function body(request){if(!request.headers.get('content-type')?.startsWith('application/json'))throw Error('json');if(Number(request.headers.get('content-length')||0)>4096)throw Error('size');const data=await request.json();if(!data||typeof data!=='object'||Array.isArray(data))throw Error('body');return data}
const sessionCookie=(token,age)=>'vina_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age='+age;
async function audit(env,actor,action,entity,id){await env.DB.prepare('INSERT INTO audit_events(id,actor_id,action,entity_type,entity_id) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),actor,action,entity,id).run()}
export default {async fetch(request,env){
const path=new URL(request.url).pathname;
if(path==='/api/health'){if(request.method!=='GET')return reply({error:'Метод не підтримується'},405);try{await env.DB.prepare('SELECT 1').first();return reply({status:'ok',database:'ready'})}catch{return reply({status:'degraded',database:'unavailable'},503)}}
if(!path.startsWith('/api/'))return env.ASSETS.fetch(request);
if(!env.DB)return reply({error:'База даних не налаштована'},503);
if(request.method==='POST'&&!sameOrigin(request))return reply({error:'Недозволене джерело запиту'},403);
try{
if(path==='/api/auth/setup-status'&&request.method==='GET'){const owner=await env.DB.prepare("SELECT id FROM employees WHERE role='owner' LIMIT 1").first();return reply({setupRequired:!owner,setupEnabled:!!env.OWNER_SETUP_TOKEN})}
if(path==='/api/auth/setup'&&request.method==='POST'){
if(!env.OWNER_SETUP_TOKEN)return reply({error:'Початкове налаштування вимкнено'},403);
const input=await body(request);
if(typeof input.token!=='string'||typeof input.name!=='string'||typeof input.password!=='string')return reply({error:'Невірні дані'},400);
if(input.name.trim().length<2||input.name.length>80||input.password.length<14||input.password.length>256)return reply({error:'Ім’я або пароль не відповідають вимогам'},400);
const provided=await sha(input.token),expected=await sha(env.OWNER_SETUP_TOKEN);if(provided!==expected)return reply({error:'Невірний код налаштування'},403);
const id=crypto.randomUUID();const hash=await passwordHash(input.password);
const result=await env.DB.prepare("INSERT INTO employees(id,display_name,role,password_hash) SELECT ?,?,'owner',? WHERE NOT EXISTS(SELECT 1 FROM employees WHERE role='owner')").bind(id,input.name.trim(),hash).run();
if(result.meta.changes!==1)return reply({error:'Власника вже створено'},409);
return reply({ok:true,message:'Обліковий запис власника створено. Вимкніть OWNER_SETUP_TOKEN у Cloudflare.'},201)
}
if(path==='/api/auth/login'&&request.method==='POST'){
const input=await body(request);if(typeof input.name!=='string'||typeof input.password!=='string'||input.name.length>80||input.password.length>256)return reply({error:'Невірні облікові дані'},401);
const employee=await env.DB.prepare("SELECT id,display_name,role,password_hash FROM employees WHERE display_name=? AND active=1 LIMIT 1").bind(input.name.trim()).first();
if(!employee||!await checkPassword(input.password,employee.password_hash))return reply({error:'Невірні облікові дані'},401);
const token=hex(crypto.getRandomValues(new Uint8Array(32)));const expiry=new Date(Date.now()+8*3600000).toISOString();
await env.DB.prepare('INSERT INTO sessions(id_hash,employee_id,expires_at) VALUES(?,?,?)').bind(await sha(token),employee.id,expiry).run();
return reply({ok:true,user:{name:employee.display_name,role:employee.role}},200,{'set-cookie':sessionCookie(token,8*3600)})
}
const user=await session(request,env);if(!user)return reply({error:'Потрібна авторизація'},401);
if(path==='/api/auth/me'&&request.method==='GET')return reply({user:{name:user.display_name,role:user.role}});
if(path==='/api/auth/logout'&&request.method==='POST'){await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE id_hash=?").bind(new Date().toISOString(),await sha(cookie(request))).run();return reply({ok:true},200,{'set-cookie':sessionCookie('',0)})}
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
if(path==='/api/staff'&&request.method==='GET'){const result=await env.DB.prepare('SELECT id,display_name,role,rank,active,created_at FROM employees ORDER BY created_at DESC LIMIT 100').all();return reply({staff:result.results})}
return reply({error:'Маршрут не знайдено'},404)
}catch(error){console.error('API error',String(error));return reply({error:'Помилка запиту або база ще не підготовлена'},500)}
}};
