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
async function audit(env,actor,action,entity,id){await env.DB.prepare('CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, details_json TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();await env.DB.prepare('INSERT INTO audit_events(id,actor_id,action,entity_type,entity_id) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),actor,action,entity,id).run()}
// Kyiv business-day boundary; uses IANA timezone rules including daylight saving time.
const kyivDateParts=instant=>{const parts=new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Kyiv',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(instant));const v=Object.fromEntries(parts.map(p=>[p.type,p.value]));return {year:Number(v.year),month:Number(v.month),day:Number(v.day)}};
const kyivLocalDate=instant=>{const p=kyivDateParts(instant);return [p.year,String(p.month).padStart(2,'0'),String(p.day).padStart(2,'0')].join('-')};
function kyivMidnightUtc(localDate){const [y,m,d]=localDate.split('-').map(Number);const target=Date.UTC(y,m-1,d);let guess=target-2*3600000;for(let i=0;i<4;i++){const parts=new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Kyiv',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(new Date(guess));const v=Object.fromEntries(parts.map(p=>[p.type,p.value]));const represented=Date.UTC(Number(v.year),Number(v.month)-1,Number(v.day),Number(v.hour),Number(v.minute),Number(v.second));guess+=target-represented;if(represented===target)break}return new Date(guess).toISOString()}
async function closeOvernightShifts(env,now=new Date()){await env.DB.prepare("CREATE TABLE IF NOT EXISTS shifts (id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES employees(id), opened_at TEXT NOT NULL, closed_at TEXT, close_reason TEXT CHECK(close_reason IN ('manual','midnight','owner')), CHECK(closed_at IS NULL OR closed_at >= opened_at))").run();const today=kyivLocalDate(now);const rows=await env.DB.prepare('SELECT id,opened_at FROM shifts WHERE closed_at IS NULL').all();let closed=0;for(const shift of rows.results||[]){if(kyivLocalDate(shift.opened_at)>=today)continue;const opened=kyivDateParts(shift.opened_at);const next=new Date(Date.UTC(opened.year,opened.month-1,opened.day+1));const boundary=kyivMidnightUtc(next.toISOString().slice(0,10));if(boundary>now.toISOString())continue;const result=await env.DB.prepare("UPDATE shifts SET closed_at=?,close_reason='midnight' WHERE id=? AND closed_at IS NULL").bind(boundary,shift.id).run();closed+=result.meta.changes||0}return closed}
export default {async scheduled(event,env,ctx){ctx.waitUntil(closeOvernightShifts(env).catch(e=>console.error('Shift midnight close failed',String(e))))},async fetch(request,env){
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
if(input.name.trim().length<2||input.name.length>80||input.password.length<8||input.password.length>256)return reply({error:'Ім’я або пароль не відповідають вимогам'},400);
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
if(path==='/api/auth/change-password'&&request.method==='POST'){
const input=await body(request);
if(typeof input.currentPassword!=='string'||typeof input.newPassword!=='string'||input.newPassword.length<(user.role==='barista'?4:8)||input.newPassword.length>256||input.currentPassword===input.newPassword)return reply({error:'Пароль бариста — від 4 символів, власника й менеджера — від 8; новий має відрізнятися від старого'},400);
const record=await env.DB.prepare('SELECT password_hash FROM employees WHERE id=?').bind(user.id).first();
if(!record||!await checkPassword(input.currentPassword,record.password_hash))return reply({error:'Поточний пароль неправильний'},403);
const hash=await passwordHash(input.newPassword);
await env.DB.prepare('UPDATE employees SET password_hash=? WHERE id=?').bind(hash,user.id).run();
await env.DB.prepare('UPDATE sessions SET revoked_at=? WHERE employee_id=?').bind(new Date().toISOString(),user.id).run();
return reply({ok:true,message:'Пароль змінено. Увійдіть повторно.'},200,{'set-cookie':sessionCookie('',0)})
}
if(path==='/api/auth/logout'&&request.method==='POST'){await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE id_hash=?").bind(new Date().toISOString(),await sha(cookie(request))).run();return reply({ok:true},200,{'set-cookie':sessionCookie('',0)})}
async function ensureShifts(){await env.DB.prepare("CREATE TABLE IF NOT EXISTS shifts (id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES employees(id), opened_at TEXT NOT NULL, closed_at TEXT, close_reason TEXT CHECK(close_reason IN ('manual','midnight','owner')), CHECK(closed_at IS NULL OR closed_at >= opened_at))").run();await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_shift ON shifts(employee_id) WHERE closed_at IS NULL').run()}
if(path.startsWith('/api/shifts')&&['GET','POST'].includes(request.method)){
await ensureShifts();
await closeOvernightShifts(env);
const now=new Date().toISOString();
if(path==='/api/shifts/mine'&&request.method==='GET'){const rows=await env.DB.prepare('SELECT id,opened_at,closed_at,close_reason FROM shifts WHERE employee_id=? ORDER BY opened_at DESC LIMIT 25').bind(user.id).all();return reply({shifts:rows.results})}
if(path==='/api/shifts/open'&&request.method==='POST'){
const id=crypto.randomUUID();
const result=await env.DB.prepare("INSERT OR IGNORE INTO shifts(id,employee_id,opened_at) VALUES(?,?,?)").bind(id,user.id,now).run();
if(result.meta.changes!==1)return reply({error:'У вас уже є відкрита зміна'},409);
return reply({ok:true,id,opened_at:now},201)}
if(path==='/api/shifts/close'&&request.method==='POST'){
const result=await env.DB.prepare("UPDATE shifts SET closed_at=?,close_reason='manual' WHERE employee_id=? AND closed_at IS NULL").bind(now,user.id).run();
if(result.meta.changes!==1)return reply({error:'Немає відкритої зміни'},409);
return reply({ok:true,closed_at:now})}
const detail=path.match(/^\/api\/shifts\/([a-f0-9-]{36})\/details$/);
if(detail&&request.method==='GET'){
 if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
 const shift=await env.DB.prepare('SELECT s.id,s.employee_id,e.display_name,s.opened_at,s.closed_at,s.close_reason FROM shifts s JOIN employees e ON e.id=s.employee_id WHERE s.id=?').bind(detail[1]).first();
 if(!shift)return reply({error:'Зміну не знайдено'},404);
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS task_templates (id TEXT PRIMARY KEY, title TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS task_completions (task_id TEXT NOT NULL REFERENCES task_templates(id), employee_id TEXT NOT NULL REFERENCES employees(id), work_date TEXT NOT NULL, completed_at TEXT NOT NULL, PRIMARY KEY(task_id,employee_id,work_date))").run();
 const end=shift.closed_at||new Date().toISOString();
 const day=kyivLocalDate(shift.opened_at);
 const completions=await env.DB.prepare("SELECT c.task_id,t.title,c.completed_at FROM task_completions c JOIN task_templates t ON t.id=c.task_id WHERE c.employee_id=? AND c.work_date=? AND c.completed_at>=? AND c.completed_at<=? ORDER BY c.completed_at ASC").bind(shift.employee_id,day,shift.opened_at,end).all();
 const assigned=await env.DB.prepare('SELECT COUNT(*) AS total FROM task_templates WHERE active=1 AND created_at<=?').bind(end).first();
 const supplies=await env.DB.prepare("SELECT COUNT(*) AS total FROM supply_requests WHERE employee_id=? AND created_at>=? AND created_at<=?").bind(shift.employee_id,shift.opened_at,end).first().catch(()=>({total:0}));
 return reply({shift,completions:completions.results||[],metrics:{completed:(completions.results||[]).length,assigned:assigned?.total||0,supplyReports:supplies?.total||0,durationMinutes:Math.max(0,Math.round((Date.parse(end)-Date.parse(shift.opened_at))/60000))}});
}
if(path==='/api/shifts'&&request.method==='GET'){
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
const rows=await env.DB.prepare('SELECT shifts.id,employees.display_name,shifts.opened_at,shifts.closed_at,shifts.close_reason FROM shifts JOIN employees ON employees.id=shifts.employee_id ORDER BY shifts.opened_at DESC LIMIT 100').all();return reply({shifts:rows.results})}
}

if(path.startsWith('/api/roster')||path.startsWith('/api/leave')){
 const admin=user.role==='owner'||user.role==='manager';
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS roster_entries(id TEXT PRIMARY KEY,employee_id TEXT NOT NULL,work_date TEXT NOT NULL,start_time TEXT NOT NULL,end_time TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL,UNIQUE(employee_id,work_date))").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS leave_requests(id TEXT PRIMARY KEY,employee_id TEXT NOT NULL,category TEXT NOT NULL,start_date TEXT NOT NULL,end_date TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'pending',manager_note TEXT NOT NULL DEFAULT '',reviewed_by TEXT,reviewed_at TEXT,created_at TEXT NOT NULL)").run();
 const day=v=>typeof v==='string'&&v.length===10&&v[4]==='-'&&v[7]==='-'&&!Number.isNaN(Date.parse(v+'T00:00:00Z'))&&new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v;
 const span=(a,b)=>Math.round((Date.parse(b+'T00:00:00Z')-Date.parse(a+'T00:00:00Z'))/86400000)+1;
 if(path==='/api/roster'&&request.method==='GET'){
  const month=new URL(request.url).searchParams.get('month')||kyivLocalDate(new Date()).slice(0,7);
  if(month.length!==7||!day(month+'-01'))return reply({error:'Невірний місяць'},400);
  const rows=await env.DB.prepare("SELECT r.*,e.display_name FROM roster_entries r JOIN employees e ON e.id=r.employee_id WHERE r.work_date LIKE ? AND (?=1 OR r.employee_id=?) ORDER BY r.work_date,r.start_time").bind(month+'%',admin?1:0,user.id).all();
  return reply({entries:rows.results});
 }
 if(path==='/api/roster'&&request.method==='POST'){
  if(!admin)return reply({error:'Недостатньо прав'},403);
  const v=await body(request);
  const time=x=>typeof x==='string'&&x.length===5&&x[2]===':'&&Number(x.slice(0,2))<24&&Number(x.slice(3))<60;
  if(!day(v.workDate)||!time(v.startTime)||!time(v.endTime)||v.startTime===v.endTime||typeof v.employeeId!=='string'||typeof(v.note||'')!=='string'||(v.note||'').length>300)return reply({error:'Перевірте дані зміни'},400);
  const staff=await env.DB.prepare("SELECT id FROM employees WHERE id=? AND active=1 AND role='barista'").bind(v.employeeId).first();
  if(!staff)return reply({error:'Працівника не знайдено'},404);
  const absent=await env.DB.prepare("SELECT id FROM leave_requests WHERE employee_id=? AND status='approved' AND category!='statement' AND start_date<=? AND end_date>=? LIMIT 1").bind(v.employeeId,v.workDate,v.workDate).first();
  if(absent)return reply({error:'На цю дату погоджена відсутність'},409);
  const id=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO roster_entries(id,employee_id,work_date,start_time,end_time,note,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(employee_id,work_date) DO UPDATE SET start_time=excluded.start_time,end_time=excluded.end_time,note=excluded.note,updated_at=excluded.updated_at").bind(id,v.employeeId,v.workDate,v.startTime,v.endTime,(v.note||'').trim(),new Date().toISOString()).run();
  await audit(env,user.id,'roster.saved','roster',id);return reply({ok:true});
 }
 if(path.startsWith('/api/roster/')&&request.method==='DELETE'){
  if(!admin)return reply({error:'Недостатньо прав'},403);
  const id=path.split('/')[3];const result=await env.DB.prepare('DELETE FROM roster_entries WHERE id=?').bind(id).run();
  if(!result.meta.changes)return reply({error:'Запис не знайдено'},404);
  await audit(env,user.id,'roster.deleted','roster',id);return reply({ok:true});
 }
 if(path==='/api/leave'&&request.method==='GET'){
  const year=Number(new URL(request.url).searchParams.get('year')||kyivLocalDate(new Date()).slice(0,4));
  if(!Number.isInteger(year)||year<2020||year>2100)return reply({error:'Невірний рік'},400);
  const rows=await env.DB.prepare("SELECT l.*,e.display_name FROM leave_requests l JOIN employees e ON e.id=l.employee_id WHERE (?=1 OR l.employee_id=?) AND (l.start_date<=? AND l.end_date>=? OR l.status='pending') ORDER BY l.created_at DESC LIMIT 250").bind(admin?1:0,user.id,year+'-12-31',year+'-01-01').all();
  const approved=await env.DB.prepare("SELECT category,start_date,end_date FROM leave_requests WHERE employee_id=? AND status='approved' AND category!='statement' AND start_date<=? AND end_date>=?").bind(user.id,year+'-12-31',year+'-01-01').all();
  const usage={day_off:0,sick_self:0,sick_document:0};
  for(const x of approved.results||[])usage[x.category]+=span(x.start_date<year+'-01-01'?year+'-01-01':x.start_date,x.end_date>year+'-12-31'?year+'-12-31':x.end_date);
  return reply({requests:rows.results,usage,limits:{day_off:24,sick_self:2,sick_document:5}});
 }
 if(path==='/api/leave'&&request.method==='POST'){
  const v=await body(request);
  if(!['day_off','sick_self','sick_document','statement'].includes(v.category)||!day(v.startDate)||!day(v.endDate)||v.endDate<v.startDate||span(v.startDate,v.endDate)>366||typeof(v.reason||'')!=='string'||(v.reason||'').length>1500)return reply({error:'Перевірте дати та текст заяви'},400);
  const id=crypto.randomUUID();
  await env.DB.prepare('INSERT INTO leave_requests(id,employee_id,category,start_date,end_date,reason,created_at) VALUES(?,?,?,?,?,?,?)').bind(id,user.id,v.category,v.startDate,v.endDate,(v.reason||'').trim(),new Date().toISOString()).run();
  await audit(env,user.id,'leave.requested','leave',id);return reply({ok:true,id},201);
 }
 if(path.startsWith('/api/leave/')&&path.endsWith('/review')&&request.method==='POST'){
  if(!admin)return reply({error:'Недостатньо прав'},403);
  const id=path.split('/')[3],v=await body(request);
  if(!['approved','rejected'].includes(v.status)||typeof(v.note||'')!=='string'||(v.note||'').length>500)return reply({error:'Невірне рішення'},400);
  const item=await env.DB.prepare("SELECT * FROM leave_requests WHERE id=? AND status='pending'").bind(id).first();
  if(!item)return reply({error:'Заяву вже розглянуто або не знайдено'},404);
  if(v.status==='approved'&&item.category!=='statement'){
   const limit={day_off:24,sick_self:2,sick_document:5}[item.category];
   for(let y=Number(item.start_date.slice(0,4));y<=Number(item.end_date.slice(0,4));y++){
    const year=String(y),start=year+'-01-01',end=year+'-12-31';
    const prev=await env.DB.prepare("SELECT start_date,end_date FROM leave_requests WHERE employee_id=? AND category=? AND status='approved' AND start_date<=? AND end_date>=?").bind(item.employee_id,item.category,end,start).all();
    let used=0;for(const x of prev.results||[])used+=span(x.start_date<start?start:x.start_date,x.end_date>end?end:x.end_date);
    if(used+span(item.start_date<start?start:item.start_date,item.end_date>end?end:item.end_date)>limit)return reply({error:'Річний ліміт '+limit+' днів буде перевищено'},409);
   }
   const clash=await env.DB.prepare("SELECT id FROM roster_entries WHERE employee_id=? AND work_date>=? AND work_date<=? LIMIT 1").bind(item.employee_id,item.start_date,item.end_date).first();
   if(clash)return reply({error:'Спочатку приберіть заплановані зміни на ці дати'},409);
   const overlap=await env.DB.prepare("SELECT id FROM leave_requests WHERE id!=? AND employee_id=? AND status='approved' AND category!='statement' AND start_date<=? AND end_date>=? LIMIT 1").bind(id,item.employee_id,item.end_date,item.start_date).first();
   if(overlap)return reply({error:'Ці дати вже погоджено в іншій заяві'},409);
  }
  await env.DB.prepare("UPDATE leave_requests SET status=?,manager_note=?,reviewed_by=?,reviewed_at=? WHERE id=? AND status='pending'").bind(v.status,(v.note||'').trim(),user.id,new Date().toISOString(),id).run();
  await audit(env,user.id,'leave.'+v.status,'leave',id);return reply({ok:true});
 }
}
// Daily checklist: owner manages templates; staff completes each item once per Kyiv date.
if(path.startsWith('/api/operations')){
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('event','announcement')), title TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', publish_at TEXT NOT NULL, event_at TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS operation_ack (operation_id TEXT NOT NULL, employee_id TEXT NOT NULL, acknowledged_at TEXT NOT NULL, PRIMARY KEY(operation_id,employee_id))").run();
 const isAdmin=user.role==='owner'||user.role==='manager';
 if(path==='/api/operations'&&request.method==='GET'){
  const rows=await env.DB.prepare("SELECT o.*,a.acknowledged_at FROM operations o LEFT JOIN operation_ack a ON a.operation_id=o.id AND a.employee_id=? WHERE (?=1 OR (o.active=1 AND o.publish_at<=?)) ORDER BY o.publish_at DESC LIMIT 100").bind(user.id,isAdmin?1:0,new Date().toISOString()).all();
  return reply({items:rows.results});
 }
 if(path==='/api/operations/summary'&&request.method==='GET'){
  if(!isAdmin)return reply({error:'Недостатньо прав'},403);
  const result=await env.DB.prepare("SELECT o.id,o.title,o.kind,o.publish_at,o.event_at,o.active,COUNT(DISTINCT e.id) AS staff_total,COUNT(DISTINCT a.employee_id) AS acknowledged_total FROM operations o LEFT JOIN employees e ON e.active=1 AND e.role='barista' LEFT JOIN operation_ack a ON a.operation_id=o.id AND a.employee_id=e.id GROUP BY o.id ORDER BY o.publish_at DESC LIMIT 100").all();
  return reply({items:result.results});
 }
 const ackList=path.match(/^\/api\/operations\/([a-f0-9-]{36})\/acknowledgments$/);
 if(ackList&&request.method==='GET'){
  if(!isAdmin)return reply({error:'Недостатньо прав'},403);
  const op=await env.DB.prepare('SELECT id FROM operations WHERE id=?').bind(ackList[1]).first();
  if(!op)return reply({error:'Подію не знайдено'},404);
  const result=await env.DB.prepare("SELECT e.id,e.display_name,a.acknowledged_at FROM employees e LEFT JOIN operation_ack a ON a.employee_id=e.id AND a.operation_id=? WHERE e.active=1 AND e.role='barista' ORDER BY a.acknowledged_at IS NULL DESC,e.display_name").bind(ackList[1]).all();
  return reply({staff:result.results});
 }
 if(path==='/api/operations'&&request.method==='POST'){
  if(!isAdmin)return reply({error:'Недостатньо прав'},403);
  const v=await body(request);
  if(!['event','announcement'].includes(v.kind)||typeof v.title!=='string'||v.title.trim().length<3||v.title.length>120||typeof v.details!=='string'||v.details.length>2000||typeof v.publishAt!=='string'||!Number.isFinite(Date.parse(v.publishAt))||v.eventAt&&(!Number.isFinite(Date.parse(v.eventAt))))return reply({error:'Перевірте дані події'},400);
  const id=crypto.randomUUID();
  await env.DB.prepare('INSERT INTO operations(id,kind,title,details,publish_at,event_at,created_at) VALUES(?,?,?,?,?,?,?)').bind(id,v.kind,v.title.trim(),v.details.trim(),new Date(v.publishAt).toISOString(),v.eventAt?new Date(v.eventAt).toISOString():null,new Date().toISOString()).run();
  await audit(env,user.id,'operation.created','operation',id);return reply({ok:true,id},201);
 }
 const match=path.match(/^\/api\/operations\/([a-f0-9-]{36})$/);
 if(match&&request.method==='PATCH'){
  if(!isAdmin)return reply({error:'Недостатньо прав'},403);
  const v=await body(request);
  if(!['event','announcement'].includes(v.kind)||typeof v.title!=='string'||v.title.trim().length<3||v.title.length>120||typeof v.details!=='string'||v.details.length>2000||typeof v.publishAt!=='string'||!Number.isFinite(Date.parse(v.publishAt))||v.eventAt&&!Number.isFinite(Date.parse(v.eventAt))||typeof v.active!=='boolean')return reply({error:'Перевірте дані'},400);
  const result=await env.DB.prepare('UPDATE operations SET kind=?,title=?,details=?,publish_at=?,event_at=?,active=? WHERE id=?').bind(v.kind,v.title.trim(),v.details.trim(),new Date(v.publishAt).toISOString(),v.eventAt?new Date(v.eventAt).toISOString():null,v.active?1:0,match[1]).run();
  if(!result.meta.changes)return reply({error:'Не знайдено'},404);
  await audit(env,user.id,'operation.updated','operation',match[1]);return reply({ok:true});
 }
 const ack=path.match(/^\/api\/operations\/([a-f0-9-]{36})\/ack$/);
 if(ack&&request.method==='POST'){
  const row=await env.DB.prepare('SELECT id FROM operations WHERE id=? AND active=1 AND publish_at<=?').bind(ack[1],new Date().toISOString()).first();
  if(!row)return reply({error:'Подія ще недоступна'},404);
  await env.DB.prepare('INSERT OR IGNORE INTO operation_ack(operation_id,employee_id,acknowledged_at) VALUES(?,?,?)').bind(ack[1],user.id,new Date().toISOString()).run();
  return reply({ok:true});
 }
}
if(path.startsWith('/api/tasks')){
await env.DB.prepare("CREATE TABLE IF NOT EXISTS task_templates (id TEXT PRIMARY KEY, title TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)").run();
await env.DB.prepare("CREATE TABLE IF NOT EXISTS task_completions (task_id TEXT NOT NULL REFERENCES task_templates(id), employee_id TEXT NOT NULL REFERENCES employees(id), work_date TEXT NOT NULL, completed_at TEXT NOT NULL, PRIMARY KEY(task_id,employee_id,work_date))").run();
const workDate=kyivLocalDate(new Date());
if(path==='/api/tasks'&&request.method==='GET'){
const rows=await env.DB.prepare("SELECT t.id,t.title,t.active,c.completed_at FROM task_templates t LEFT JOIN task_completions c ON c.task_id=t.id AND c.employee_id=? AND c.work_date=? WHERE t.active=1 OR ? IN ('owner','manager') ORDER BY t.created_at,t.id").bind(user.id,workDate,user.role).all();return reply({date:workDate,tasks:rows.results})}
if(path==='/api/tasks/completions'&&request.method==='GET'){
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
const rows=await env.DB.prepare("SELECT c.task_id,t.title,c.employee_id,e.display_name,c.work_date,c.completed_at FROM task_completions c JOIN task_templates t ON t.id=c.task_id JOIN employees e ON e.id=c.employee_id WHERE c.work_date=? ORDER BY c.completed_at DESC LIMIT 200").bind(workDate).all();
return reply({date:workDate,completions:rows.results});
}
if(path==='/api/tasks'&&request.method==='POST'){
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
const input=await body(request);if(typeof input.title!=='string'||input.title.trim().length<3||input.title.trim().length>120)return reply({error:'Назва завдання має містити від 3 до 120 символів'},400);
const id=crypto.randomUUID();await env.DB.prepare('INSERT INTO task_templates(id,title,created_at) VALUES(?,?,?)').bind(id,input.title.trim(),new Date().toISOString()).run();await audit(env,user.id,'task.created','task',id);return reply({ok:true,id},201)}
const edit=path.match(/^\/api\/tasks\/([a-f0-9-]{36})$/);
if(edit&&request.method==='PATCH'){
 if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
 const input=await body(request);
 if(typeof input.title!=='string'||input.title.trim().length<3||input.title.trim().length>120)return reply({error:'Назва завдання має містити від 3 до 120 символів'},400);
 const result=await env.DB.prepare('UPDATE task_templates SET title=? WHERE id=?').bind(input.title.trim(),edit[1]).run();
 if(!result.meta.changes)return reply({error:'Завдання не знайдено'},404);
 await audit(env,user.id,'task.edited','task',edit[1]);
 return reply({ok:true});
}
const completion=path.match(/^\/api\/tasks\/([a-f0-9-]{36})\/complete$/);
if(completion&&request.method==='POST'){
const task=await env.DB.prepare('SELECT id FROM task_templates WHERE id=? AND active=1').bind(completion[1]).first();if(!task)return reply({error:'Завдання не знайдено'},404);
await env.DB.prepare('INSERT OR IGNORE INTO task_completions(task_id,employee_id,work_date,completed_at) VALUES(?,?,?,?)').bind(task.id,user.id,workDate,new Date().toISOString()).run();return reply({ok:true,date:workDate})}
const status=path.match(/^\/api\/tasks\/([a-f0-9-]{36})\/status$/);
if(status&&request.method==='POST'){
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
const input=await body(request);if(typeof input.active!=='boolean')return reply({error:'Невірний статус'},400);
const result=await env.DB.prepare('UPDATE task_templates SET active=? WHERE id=?').bind(input.active?1:0,status[1]).run();if(!result.meta.changes)return reply({error:'Завдання не знайдено'},404);await audit(env,user.id,input.active?'task.enabled':'task.disabled','task',status[1]);return reply({ok:true})}
}
// Inventory quantities are owner-managed; staff only sees item names.
if(path.startsWith('/api/inventory')){
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS inventory_items (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, quantity REAL NOT NULL DEFAULT 0 CHECK(quantity>=0), unit TEXT NOT NULL DEFAULT 'шт', critical INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)").run();
 if(path==='/api/inventory/catalog'&&request.method==='GET'){
  const rows=await env.DB.prepare('SELECT id,name FROM inventory_items ORDER BY name LIMIT 200').all();
  return reply({items:rows.results});
 }
 if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
 if(path==='/api/inventory'&&request.method==='GET'){
  const rows=await env.DB.prepare('SELECT id,name,quantity,unit,critical,updated_at FROM inventory_items ORDER BY critical DESC,name LIMIT 200').all();
  return reply({items:rows.results});
 }
 if(path==='/api/inventory/alerts'&&request.method==='GET'){
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS supply_requests (id TEXT PRIMARY KEY, employee_id TEXT NOT NULL, item_name TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','resolved')), created_at TEXT NOT NULL, resolved_at TEXT)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS supply_request_details (request_id TEXT PRIMARY KEY, item_id TEXT NOT NULL, stock_state TEXT NOT NULL CHECK(stock_state IN ('empty','low')))").run();
  const result=await env.DB.prepare("SELECT r.id,r.item_name,r.created_at,COALESCE(d.stock_state,'empty') AS stock_state FROM supply_requests r LEFT JOIN supply_request_details d ON d.request_id=r.id WHERE r.status='new' ORDER BY r.created_at DESC LIMIT 20").all();
  return reply({alerts:result.results});
 }
 if(path==='/api/inventory'&&request.method==='POST'){
  const input=await body(request);
  if(typeof input.name!=='string'||input.name.trim().length<2||input.name.trim().length>100||typeof input.quantity!=='number'||!Number.isFinite(input.quantity)||input.quantity<0||input.quantity>1000000||typeof input.unit!=='string'||input.unit.trim().length<1||input.unit.length>20||typeof input.critical!=='boolean')return reply({error:'Перевірте назву, кількість, одиницю та важливість'},400);
  const id=crypto.randomUUID();
  await env.DB.prepare('INSERT INTO inventory_items(id,name,quantity,unit,critical,updated_at) VALUES(?,?,?,?,?,?)').bind(id,input.name.trim(),input.quantity,input.unit.trim(),input.critical?1:0,new Date().toISOString()).run();
  await audit(env,user.id,'inventory.created','inventory',id);
  return reply({ok:true,id},201);
 }
 const match=path.match(/^\/api\/inventory\/([a-f0-9-]{36})$/);
 if(match&&request.method==='DELETE'){
  if(user.role!=='owner')return reply({error:'Видаляти товари може лише власник'},403);
  const item=await env.DB.prepare('SELECT id,name FROM inventory_items WHERE id=?').bind(match[1]).first();
  if(!item)return reply({error:'Товар не знайдено'},404);
  await env.DB.prepare('DELETE FROM inventory_items WHERE id=?').bind(item.id).run();
  await audit(env,user.id,'inventory.deleted','inventory',item.id);
  return reply({ok:true});
 }
 if(match&&request.method==='PATCH'){
  const input=await body(request);
  if(typeof input.name!=='string'||input.name.trim().length<2||input.name.trim().length>100||typeof input.quantity!=='number'||!Number.isFinite(input.quantity)||input.quantity<0||input.quantity>1000000||typeof input.unit!=='string'||!input.unit.trim()||input.unit.length>20||typeof input.critical!=='boolean')return reply({error:'Перевірте дані товару'},400);
  const duplicate=await env.DB.prepare('SELECT id FROM inventory_items WHERE name=? COLLATE NOCASE AND id<>?').bind(input.name.trim(),match[1]).first();
  if(duplicate)return reply({error:'Товар з такою назвою вже існує'},409);
  const result=await env.DB.prepare('UPDATE inventory_items SET name=?,quantity=?,unit=?,critical=?,updated_at=? WHERE id=?').bind(input.name.trim(),input.quantity,input.unit.trim(),input.critical?1:0,new Date().toISOString(),match[1]).run();
  if(!result.meta.changes)return reply({error:'Товар не знайдено'},404);
  await audit(env,user.id,'inventory.edited','inventory',match[1]);return reply({ok:true});
 }
 if(match&&request.method==='POST'){
  const input=await body(request);
  if(typeof input.quantity!=='number'||!Number.isFinite(input.quantity)||input.quantity<0||input.quantity>1000000)return reply({error:'Невірна кількість'},400);
  const result=await env.DB.prepare('UPDATE inventory_items SET quantity=?,updated_at=? WHERE id=?').bind(input.quantity,new Date().toISOString(),match[1]).run();
  if(!result.meta.changes)return reply({error:'Товар не знайдено'},404);
  await audit(env,user.id,'inventory.adjusted','inventory',match[1]);return reply({ok:true});
 }
}
// Supply requests do not expose inventory balances to staff.
if(path.startsWith('/api/supply-requests')){
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS supply_request_details (request_id TEXT PRIMARY KEY, item_id TEXT NOT NULL, stock_state TEXT NOT NULL CHECK(stock_state IN ('empty','low')))").run();

 await env.DB.prepare("CREATE TABLE IF NOT EXISTS inventory_items (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, quantity REAL NOT NULL DEFAULT 0 CHECK(quantity>=0), unit TEXT NOT NULL DEFAULT 'шт', critical INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS supply_requests (id TEXT PRIMARY KEY, employee_id TEXT NOT NULL, item_name TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','resolved')), created_at TEXT NOT NULL, resolved_at TEXT)").run();
 if(path==='/api/supply-requests'&&request.method==='POST'){
  const input=await body(request);
  if(!['empty','low'].includes(input.stockState)||typeof input.itemId!=='string'||!/^[a-f0-9-]{36}$/.test(input.itemId)||typeof input.note!=='string'||input.note.length>300)return reply({error:'Оберіть товар зі складу; примітка — до 300 символів'},400);
  const item=await env.DB.prepare('SELECT id,name FROM inventory_items WHERE id=?').bind(input.itemId).first();
  if(!item)return reply({error:'Товар не знайдено у складі'},404);
  const id=crypto.randomUUID(),now=new Date().toISOString();
  await env.DB.batch([
   ...(input.stockState==='empty'?[env.DB.prepare('UPDATE inventory_items SET quantity=0,updated_at=? WHERE id=?').bind(now,item.id)]:[]),
   env.DB.prepare('INSERT INTO supply_requests(id,employee_id,item_name,note,created_at) VALUES(?,?,?,?,?)').bind(id,user.id,item.name,input.note.trim(),now),
   env.DB.prepare('INSERT INTO supply_request_details(request_id,item_id,stock_state) VALUES(?,?,?)').bind(id,item.id,input.stockState)
  ]);
  if(input.stockState==='empty')await audit(env,user.id,'inventory.reported_empty','inventory',item.id);
  await audit(env,user.id,'supply.requested','supply_request',id);
  return reply({ok:true,id,itemId:item.id,stockState:input.stockState},201);
 }
 if(path==='/api/supply-requests'&&request.method==='GET'){
  if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
  const rows=await env.DB.prepare("SELECT r.id,r.item_name,r.note,r.status,r.created_at,r.resolved_at,e.display_name,COALESCE(d.stock_state,'empty') AS stock_state FROM supply_requests r JOIN employees e ON e.id=r.employee_id LEFT JOIN supply_request_details d ON d.request_id=r.id ORDER BY CASE r.status WHEN 'new' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 150").all();
  return reply({requests:rows.results});
 }
 const match=path.match(/^\/api\/supply-requests\/([a-f0-9-]{36})\/resolve$/);
 if(match&&request.method==='POST'){
  if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
  const result=await env.DB.prepare("UPDATE supply_requests SET status='resolved',resolved_at=? WHERE id=? AND status='new'").bind(new Date().toISOString(),match[1]).run();
  if(!result.meta.changes)return reply({error:'Заявку не знайдено або вже опрацьовано'},404);
  await audit(env,user.id,'supply.resolved','supply_request',match[1]);
  return reply({ok:true});
 }
}
if(path==='/api/staff/me'&&request.method==='GET')return reply({user:{name:user.display_name,role:user.role},modules:{shifts:true,bonuses:false,tasks:true,stockReports:false}});
if(user.role!=='owner'&&user.role!=='manager')return reply({error:'Недостатньо прав'},403);
if(path==='/api/staff'&&request.method==='GET'){const result=await env.DB.prepare('SELECT id,display_name,role,rank,active,created_at FROM employees ORDER BY created_at DESC LIMIT 100').all();return reply({staff:result.results})}
if(path==='/api/audit'&&request.method==='GET'){await env.DB.prepare('CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, details_json TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();const result=await env.DB.prepare('SELECT action,entity_type,created_at FROM audit_events ORDER BY created_at DESC LIMIT 40').all();return reply({events:result.results})}
if(path==='/api/staff'&&request.method==='POST'){
if(user.role!=='owner')return reply({error:'Лише власник може створювати працівників'},403);
const input=await body(request);
if(typeof input.name!=='string'||typeof input.password!=='string'||!['barista','manager'].includes(input.role)||input.name.trim().length<2||input.name.trim().length>80||input.password.length<(input.role==='barista'?4:8)||input.password.length>256)return reply({error:'Пароль бариста — від 4 символів, менеджера — від 8'},400);
const exists=await env.DB.prepare('SELECT id FROM employees WHERE display_name=? LIMIT 1').bind(input.name.trim()).first();if(exists)return reply({error:'Працівник з таким ім’ям уже існує'},409);
const id=crypto.randomUUID(),hash=await passwordHash(input.password);
await env.DB.prepare('INSERT INTO employees(id,display_name,role,password_hash) VALUES(?,?,?,?)').bind(id,input.name.trim(),input.role,hash).run();
await audit(env,user.id,'employee.created','employee',id);
return reply({ok:true},201)
}
const match=path.match(/^\/api\/staff\/([a-f0-9-]{36})\/status$/);
if(match&&request.method==='POST'){
if(user.role!=='owner')return reply({error:'Лише власник може змінювати доступ'},403);
if(match[1]===user.id)return reply({error:'Не можна вимкнути власний обліковий запис'},400);
const input=await body(request);if(typeof input.active!=='boolean')return reply({error:'Невірний статус'},400);
const target=await env.DB.prepare('SELECT id,role FROM employees WHERE id=?').bind(match[1]).first();
if(!target)return reply({error:'Працівника не знайдено'},404);
if(target.role==='owner')return reply({error:'Не можна змінювати статус власника'},403);
await env.DB.prepare('UPDATE employees SET active=? WHERE id=?').bind(input.active?1:0,match[1]).run();
if(!input.active)await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE employee_id=? AND revoked_at IS NULL").bind(new Date().toISOString(),match[1]).run();
await audit(env,user.id,input.active?'employee.enabled':'employee.disabled','employee',match[1]);
return reply({ok:true})
}
return reply({error:'Маршрут не знайдено'},404)
}catch(error){console.error('API error',String(error));return reply({error:'Помилка запиту або база ще не підготовлена'},500)}
}};
