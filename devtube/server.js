const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

loadEnv();
const PORT = Number(process.env.PORT || 3000);
const ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const db = new DatabaseSync(path.join(__dirname, 'devtube.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT, provider TEXT NOT NULL DEFAULT 'email', provider_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER NOT NULL, video_id TEXT NOT NULL, title TEXT, thumbnail TEXT, channel TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,video_id));
CREATE TABLE IF NOT EXISTS history(user_id INTEGER NOT NULL, video_id TEXT NOT NULL, title TEXT, thumbnail TEXT, channel TEXT, watched_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,video_id));`);

const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.json':'application/json; charset=utf-8'};
const json=(res,code,data)=>{res.writeHead(code,{'Content-Type':mime['.json']});res.end(JSON.stringify(data));};
const parseCookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>x.trim().split('=').map(decodeURIComponent)));
const body=async req=>{let s='';for await(const c of req){s+=c;if(s.length>1e6)throw Error('Request too large');}return s?JSON.parse(s):{};};
const b64=x=>Buffer.from(x).toString('base64url');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function passwordHash(p){const salt=crypto.randomBytes(16);return `${salt.toString('hex')}:${crypto.scryptSync(p,salt,64).toString('hex')}`}
function passwordOk(p,stored){if(!stored)return false;const [s,h]=stored.split(':');return crypto.timingSafeEqual(Buffer.from(h,'hex'),crypto.scryptSync(p,Buffer.from(s,'hex'),64));}
function sessionUser(req){const token=parseCookies(req).devtube_session;if(!token)return null;return db.prepare(`SELECT u.id,u.email,u.name,u.provider FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(hash(token),Date.now())||null;}
function makeSession(res,userId){const token=b64(crypto.randomBytes(32));db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),userId,Date.now()+30*864e5);res.setHeader('Set-Cookie',`devtube_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${ORIGIN.startsWith('https')?'; Secure':''}`);}
function requireUser(req,res){const u=sessionUser(req);if(!u)json(res,401,{error:'Please sign in first.'});return u;}

async function youtube(endpoint,params={}){if(!process.env.YOUTUBE_API_KEY)throw Object.assign(Error('Add YOUTUBE_API_KEY to .env to search YouTube.'),{status:503});const u=new URL(`https://www.googleapis.com/youtube/v3/${endpoint}`);Object.entries({...params,key:process.env.YOUTUBE_API_KEY}).forEach(([k,v])=>u.searchParams.set(k,v));const r=await fetch(u);const d=await r.json();if(!r.ok)throw Object.assign(Error(d.error?.message||'YouTube request failed'),{status:r.status});return d;}
function videoShape(item){const s=item.snippet||{};return {id:item.id.videoId||item.id,title:s.title,channel:s.channelTitle,thumbnail:s.thumbnails?.high?.url||s.thumbnails?.medium?.url||s.thumbnails?.default?.url,publishedAt:s.publishedAt,description:s.description||''};}
const oauth={
 google:{auth:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',user:'https://openidconnect.googleapis.com/v1/userinfo',scope:'openid email profile',id:'GOOGLE_CLIENT_ID',secret:'GOOGLE_CLIENT_SECRET'},
 microsoft:{auth:'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',token:'https://login.microsoftonline.com/common/oauth2/v2.0/token',user:'https://graph.microsoft.com/oidc/userinfo',scope:'openid email profile',id:'MICROSOFT_CLIENT_ID',secret:'MICROSOFT_CLIENT_SECRET'},
 apple:{auth:'https://appleid.apple.com/auth/authorize',token:'https://appleid.apple.com/auth/token',user:null,scope:'name email',id:'APPLE_CLIENT_ID',secret:'APPLE_CLIENT_SECRET'}
};
function decodeJwt(t){try{return JSON.parse(Buffer.from(t.split('.')[1],'base64url').toString())}catch{return {}}}

async function api(req,res,url){
 if(req.method==='GET'&&url.pathname==='/api/health')return json(res,200,{ok:true,youtubeConfigured:!!process.env.YOUTUBE_API_KEY});
 if(req.method==='GET'&&url.pathname==='/api/auth/me')return json(res,200,{user:sessionUser(req)});
 if(req.method==='POST'&&url.pathname==='/api/auth/signup'){const d=await body(req);if(!/^\S+@\S+\.\S+$/.test(d.email||'')||(d.password||'').length<8||!(d.name||'').trim())return json(res,400,{error:'Enter a name, valid email and password of 8+ characters.'});try{const r=db.prepare('INSERT INTO users(email,name,password_hash) VALUES(?,?,?)').run(d.email.toLowerCase(),d.name.trim(),passwordHash(d.password));makeSession(res,Number(r.lastInsertRowid));return json(res,201,{ok:true});}catch(e){return json(res,409,{error:'An account with that email already exists.'});}}
 if(req.method==='POST'&&url.pathname==='/api/auth/login'){const d=await body(req);const u=db.prepare('SELECT * FROM users WHERE email=?').get((d.email||'').toLowerCase());if(!u||!passwordOk(d.password||'',u.password_hash))return json(res,401,{error:'Incorrect email or password.'});makeSession(res,u.id);return json(res,200,{ok:true});}
 if(req.method==='POST'&&url.pathname==='/api/auth/logout'){const c=parseCookies(req);if(c.devtube_session)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(c.devtube_session));res.setHeader('Set-Cookie','devtube_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return json(res,200,{ok:true});}
 if(req.method==='GET'&&url.pathname.startsWith('/api/auth/oauth/')){const provider=url.pathname.split('/').pop(),o=oauth[provider];if(!o)return json(res,404,{error:'Provider not found'});if(!process.env[o.id]||!process.env[o.secret])return json(res,503,{error:`${provider[0].toUpperCase()+provider.slice(1)} login needs credentials in .env.`});const state=b64(crypto.randomBytes(18));res.setHeader('Set-Cookie',`oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`);const a=new URL(o.auth);a.searchParams.set('client_id',process.env[o.id]);a.searchParams.set('redirect_uri',`${ORIGIN}/api/auth/callback/${provider}`);a.searchParams.set('response_type','code');a.searchParams.set('scope',o.scope);a.searchParams.set('state',state);if(provider==='google')a.searchParams.set('access_type','online');if(provider==='apple')a.searchParams.set('response_mode','query');res.writeHead(302,{Location:a});return res.end();}
 if(req.method==='GET'&&url.pathname.startsWith('/api/auth/callback/')){const provider=url.pathname.split('/').pop(),o=oauth[provider],c=parseCookies(req);if(!o||url.searchParams.get('state')!==c.oauth_state)return json(res,400,{error:'Invalid OAuth state'});const form=new URLSearchParams({grant_type:'authorization_code',code:url.searchParams.get('code')||'',redirect_uri:`${ORIGIN}/api/auth/callback/${provider}`,client_id:process.env[o.id],client_secret:process.env[o.secret]});const tr=await fetch(o.token,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form});const td=await tr.json();if(!tr.ok)throw Error(td.error_description||'OAuth token exchange failed');let profile=o.user?await fetch(o.user,{headers:{Authorization:`Bearer ${td.access_token}`}}).then(r=>r.json()):decodeJwt(td.id_token);const email=(profile.email||'').toLowerCase(),pid=profile.sub;if(!email)return json(res,400,{error:'The provider did not return an email.'});let u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u){const name=profile.name||email.split('@')[0];const r=db.prepare('INSERT INTO users(email,name,provider,provider_id) VALUES(?,?,?,?)').run(email,name,provider,pid);u={id:Number(r.lastInsertRowid)};}makeSession(res,u.id);res.writeHead(302,{Location:ORIGIN});return res.end();}
 if(req.method==='GET'&&url.pathname==='/api/videos'){const q=url.searchParams.get('q')||'',pageToken=url.searchParams.get('pageToken')||'';const d=await youtube('search',{part:'snippet',type:'video',maxResults:'18',safeSearch:'moderate',videoEmbeddable:'true',q,order:q?'relevance':'viewCount',...(pageToken?{pageToken}:{})});return json(res,200,{videos:d.items.map(videoShape),nextPageToken:d.nextPageToken||null});}
 if(url.pathname==='/api/favorites'&&req.method==='GET'){const u=requireUser(req,res);if(!u)return;return json(res,200,{videos:db.prepare('SELECT video_id id,title,thumbnail,channel FROM favorites WHERE user_id=? ORDER BY created_at DESC').all(u.id)});}
 if(url.pathname==='/api/history'&&req.method==='GET'){const u=requireUser(req,res);if(!u)return;return json(res,200,{videos:db.prepare('SELECT video_id id,title,thumbnail,channel FROM history WHERE user_id=? ORDER BY watched_at DESC').all(u.id)});}
 if((url.pathname==='/api/favorites'||url.pathname==='/api/history')&&req.method==='POST'){const u=requireUser(req,res);if(!u)return;const d=await body(req),table=url.pathname.slice(5);if(!/^[\w-]{6,20}$/.test(d.id||''))return json(res,400,{error:'Invalid video.'});if(table==='favorites')db.prepare('INSERT OR REPLACE INTO favorites(user_id,video_id,title,thumbnail,channel) VALUES(?,?,?,?,?)').run(u.id,d.id,d.title,d.thumbnail,d.channel);else db.prepare('INSERT OR REPLACE INTO history(user_id,video_id,title,thumbnail,channel,watched_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)').run(u.id,d.id,d.title,d.thumbnail,d.channel);return json(res,200,{ok:true});}
 if(url.pathname.startsWith('/api/favorites/')&&req.method==='DELETE'){const u=requireUser(req,res);if(!u)return;db.prepare('DELETE FROM favorites WHERE user_id=? AND video_id=?').run(u.id,url.pathname.split('/').pop());return json(res,200,{ok:true});}
 return json(res,404,{error:'Not found'});
}

const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,ORIGIN);if(url.pathname.startsWith('/api/'))return await api(req,res,url);let file=path.join(__dirname,'public',url.pathname==='/'?'index.html':url.pathname);if(!file.startsWith(path.join(__dirname,'public')))return json(res,403,{error:'Forbidden'});fs.readFile(file,(e,data)=>{if(e){res.writeHead(404);res.end('Not found');}else{res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache'});res.end(data);}});}catch(e){console.error(e);json(res,e.status||500,{error:e.message||'Server error'});}});
server.listen(PORT,()=>console.log(`DevTube running at ${ORIGIN}`));
function loadEnv(){const f=path.join(__dirname,'.env');if(!fs.existsSync(f))return;for(const line of fs.readFileSync(f,'utf8').split(/\r?\n/)){const m=line.match(/^([A-Z0-9_]+)=(.*)$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^['"]|['"]$/g,'');}}
