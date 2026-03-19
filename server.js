#!/usr/bin/env node
// server.js — zero external dependencies, Node.js native only
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const CDP_PORTS = [9000, 9001, 9002, 9003];
const DISCOVERY_INTERVAL = 10000;
const POLL_INTERVAL = 3000;

// --- State ---
let cascades = new Map();
const wsClients = new Set();

// --- WebSocket (RFC 6455) ---
function wsHandshake(req, socket) {
    const key = req.headers['sec-websocket-key'];
    const accept = crypto
        .createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        .digest('base64');
    socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );
}

function wsDecodeFrame(buf) {
    if (buf.length < 2) return null;
    const fin = (buf[0] & 0x80) !== 0;
    const opcode = buf[0] & 0x0f;
    const masked = (buf[1] & 0x80) !== 0;
    let payloadLen = buf[1] & 0x7f;
    let offset = 2;
    if (payloadLen === 126) { payloadLen = buf.readUInt16BE(2); offset = 4; }
    else if (payloadLen === 127) { payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
    if (buf.length < offset + (masked ? 4 : 0) + payloadLen) return null;
    const mask = masked ? buf.slice(offset, offset + 4) : null;
    if (masked) offset += 4;
    const payload = buf.slice(offset, offset + payloadLen);
    if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    return { opcode, payload: payload.toString('utf8'), fin };
}

function wsEncodeFrame(data) {
    const payload = Buffer.from(data, 'utf8');
    const len = payload.length;
    let header;
    if (len < 126) {
        header = Buffer.alloc(2);
        header[0] = 0x81;
        header[1] = len;
    } else if (len < 65536) {
        header = Buffer.alloc(4);
        header[0] = 0x81;
        header[1] = 126;
        header.writeUInt16BE(len, 2);
    } else {
        header = Buffer.alloc(10);
        header[0] = 0x81;
        header[1] = 127;
        header.writeBigUInt64BE(BigInt(len), 2);
    }
    return Buffer.concat([header, payload]);
}

function wsBroadcast(obj) {
    const frame = wsEncodeFrame(JSON.stringify(obj));
    for (const sock of wsClients) {
        try { sock.write(frame); } catch (e) { wsClients.delete(sock); }
    }
}

// --- Helpers ---
function hashString(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) { h = ((h << 5) - h) + str.charCodeAt(i); h = h & h; }
    return Math.abs(h).toString(36);
}

function getJson(url) {
    return new Promise((resolve) => {
        const req = http.get(url, (res) => {
            let d = '';
            res.on('data', c => d += c);
            res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve([]); } });
        });
        req.on('error', () => resolve([]));
        req.setTimeout(2000, () => { req.destroy(); resolve([]); });
    });
}

function getMime(ext) {
    return { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' }[ext] || 'application/octet-stream';
}

// --- CDP Logic ---
function cdpConnect(wsUrl) {
    return new Promise((resolve, reject) => {
        // Parse ws:// URL
        const m = wsUrl.match(/^ws:\/\/([^/:]+):?(\d+)?(\/.*)$/);
        if (!m) return reject(new Error('bad url'));
        const host = m[1], port = parseInt(m[2] || '80', 10), urlPath = m[3];
        const key = crypto.randomBytes(16).toString('base64');

        const sock = new (await import('node:net').then(n => n)).Socket();
        // Use raw TCP approach
        return reject(new Error('Use built-in approach')); // fallback below
    });
}

// Use Node's built-in http to upgrade for CDP WebSocket
function cdpConnectHTTP(wsUrl) {
    return new Promise((resolve, reject) => {
        const m = wsUrl.match(/^ws:\/\/([^/:]+):?(\d+)?(\/.*)$/);
        if (!m) return reject(new Error('bad ws url: ' + wsUrl));
        const host = m[1], port = parseInt(m[2] || '80', 10), urlPath = m[3];
        const key = crypto.randomBytes(16).toString('base64');

        const req = http.request({ host, port, path: urlPath, headers: { 'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13' } });
        req.on('upgrade', (res, socket) => {
            let idCounter = 1;
            const pending = new Map();
            const contexts = [];
            let buf = Buffer.alloc(0);

            socket.on('data', (chunk) => {
                buf = Buffer.concat([buf, chunk]);
                while (buf.length >= 2) {
                    const frame = wsDecodeFrame(buf);
                    if (!frame) break;
                    const consumed = frameSize(buf);
                    buf = buf.slice(consumed);
                    if (frame.opcode === 8) { socket.destroy(); break; }
                    if (frame.opcode !== 1) continue;
                    try {
                        const data = JSON.parse(frame.payload);
                        if (data.id && pending.has(data.id)) {
                            const { resolve, reject } = pending.get(data.id);
                            pending.delete(data.id);
                            if (data.error) reject(data.error); else resolve(data.result);
                        }
                        if (data.method === 'Runtime.executionContextCreated') contexts.push(data.params.context);
                        else if (data.method === 'Runtime.executionContextDestroyed') {
                            const idx = contexts.findIndex(c => c.id === data.params.executionContextId);
                            if (idx !== -1) contexts.splice(idx, 1);
                        }
                    } catch (e) { }
                }
            });
            socket.on('error', () => { });
            socket.on('close', () => { });

            const call = (method, params) => new Promise((res, rej) => {
                const id = idCounter++;
                pending.set(id, { resolve: res, reject: rej });
                const payload = Buffer.from(JSON.stringify({ id, method, params }), 'utf8');
                const header = Buffer.alloc(payload.length < 126 ? 2 : 4);
                header[0] = 0x81;
                const mask = crypto.randomBytes(4);
                if (payload.length < 126) { header[1] = 0x80 | payload.length; }
                else { header[1] = 0x80 | 126; header.writeUInt16BE(payload.length, 2); }
                const masked = Buffer.from(payload);
                for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
                socket.write(Buffer.concat([header, mask, masked]));
                setTimeout(() => { if (pending.has(id)) { pending.delete(id); rej(new Error('timeout')); } }, 5000);
            });

            resolve({ socket, call, contexts, rootContextId: null });
        });
        req.on('error', reject);
        req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
        req.end();
    });
}

function frameSize(buf) {
    if (buf.length < 2) return 0;
    const masked = (buf[1] & 0x80) !== 0;
    let payloadLen = buf[1] & 0x7f;
    let offset = 2;
    if (payloadLen === 126) { payloadLen = buf.readUInt16BE(2); offset = 4; }
    else if (payloadLen === 127) { payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
    return offset + (masked ? 4 : 0) + payloadLen;
}

async function extractMetadata(cdp) {
    const SCRIPT = `(()=>{const el=document.getElementById('cascade')||document.querySelector('main')||document.querySelector('#root')||document.body;if(!el)return{found:false};let title=null;for(const s of['h1','h2','header','[class*="title"]']){const e=document.querySelector(s);if(e&&e.textContent.length>2&&e.textContent.length<50){title=e.textContent.trim();break;}}return{found:true,chatTitle:title||'Agent',isActive:document.hasFocus()};})()`;
    if (cdp.rootContextId) {
        try {
            const r = await cdp.call('Runtime.evaluate', { expression: SCRIPT, returnByValue: true, contextId: cdp.rootContextId });
            if (r.result?.value?.found) return { ...r.result.value, contextId: cdp.rootContextId };
        } catch { cdp.rootContextId = null; }
    }
    for (const ctx of cdp.contexts) {
        try {
            const r = await cdp.call('Runtime.evaluate', { expression: SCRIPT, returnByValue: true, contextId: ctx.id });
            if (r.result?.value?.found) return { ...r.result.value, contextId: ctx.id };
        } catch { }
    }
    return null;
}

async function captureCSS(cdp) {
    const SCRIPT = `(()=>{let css='';for(const s of document.styleSheets){try{for(const r of s.cssRules){let t=r.cssText;t=t.replace(/(^|[\\s,}])body(?=[\\s,{])/gi,'$1#cascade');t=t.replace(/(^|[\\s,}])html(?=[\\s,{])/gi,'$1#cascade');css+=t+'\\n';}}catch(e){}}return{css};})()`;
    if (!cdp.rootContextId) return '';
    try {
        const r = await cdp.call('Runtime.evaluate', { expression: SCRIPT, returnByValue: true, contextId: cdp.rootContextId });
        return r.result?.value?.css || '';
    } catch { return ''; }
}

async function captureHTML(cdp) {
    const SCRIPT = `(()=>{const el=document.getElementById('cascade')||document.querySelector('main')||document.querySelector('#root')||document.body;if(!el)return{error:'not found'};const clone=el.cloneNode(true);if(clone.tagName==='BODY'||!clone.id)clone.id='cascade';const inp=clone.querySelector('[contenteditable="true"]')?.closest('div[id^="cascade"]>div');if(inp)inp.remove();const bs=window.getComputedStyle(document.body);return{html:clone.outerHTML,bodyBg:bs.backgroundColor,bodyColor:bs.color};})()`;
    if (!cdp.rootContextId) return null;
    try {
        const r = await cdp.call('Runtime.evaluate', { expression: SCRIPT, returnByValue: true, contextId: cdp.rootContextId });
        if (r.result?.value && !r.result.value.error) return r.result.value;
    } catch { }
    return null;
}

async function injectMessage(cdp, text) {
    const escaped = text.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    const SCRIPT = `(async()=>{const ed=document.querySelector('[contenteditable="true"]')||document.querySelector('[contenteditable="plaintext-only"]')||document.querySelector('[contenteditable]')||document.querySelector('textarea');if(!ed)return{ok:false,reason:'no editor'};ed.focus();if(ed.tagName==='TEXTAREA'){const s=Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype,'value').set;s.call(ed,"${escaped}");ed.dispatchEvent(new Event('input',{bubbles:true}));}else{document.execCommand('selectAll',false,null);document.execCommand('insertText',false,"${escaped}");}await new Promise(r=>setTimeout(r,100));const btn=document.querySelector('button[class*="arrow"]')||document.querySelector('button[aria-label*="Send"]')||document.querySelector('button[aria-label*="Enviar"]')||document.querySelector('button[type="submit"]');if(btn){btn.click();}else{ed.dispatchEvent(new KeyboardEvent('keydown',{bubbles:true,key:'Enter',code:'Enter',keyCode:13,which:13}));ed.dispatchEvent(new KeyboardEvent('keyup',{bubbles:true,key:'Enter',code:'Enter',keyCode:13,which:13}));}return{ok:true};})()`;
    try {
        const r = await cdp.call('Runtime.evaluate', { expression: SCRIPT, returnByValue: true, contextId: cdp.rootContextId });
        return r.result?.value || { ok: false };
    } catch (e) { return { ok: false, reason: e.message }; }
}

// --- Discovery ---
async function discover() {
    const allTargets = [];
    await Promise.all(CDP_PORTS.map(async (port) => {
        const list = await getJson(`http://127.0.0.1:${port}/json/list`);
        list.filter(t => t.url?.includes('workbench.html') || t.title?.includes('workbench')).forEach(t => allTargets.push({ ...t, port }));
    }));

    const newCascades = new Map();
    for (const target of allTargets) {
        const id = hashString(target.webSocketDebuggerUrl);
        if (cascades.has(id)) {
            const ex = cascades.get(id);
            if (!ex.cdp.socket.destroyed) {
                const meta = await extractMetadata(ex.cdp).catch(() => null);
                if (meta) { ex.metadata = { ...ex.metadata, ...meta }; if (meta.contextId) ex.cdp.rootContextId = meta.contextId; newCascades.set(id, ex); continue; }
            }
        }
        try {
            console.log(`🔌 Connecting to ${target.title}`);
            const cdp = await cdpConnectHTTP(target.webSocketDebuggerUrl);
            await cdp.call('Runtime.enable', {});
            await new Promise(r => setTimeout(r, 500));
            const meta = await extractMetadata(cdp);
            if (meta) {
                if (meta.contextId) cdp.rootContextId = meta.contextId;
                const cascade = { id, cdp, metadata: { windowTitle: target.title, chatTitle: meta.chatTitle, isActive: meta.isActive }, snapshot: null, css: await captureCSS(cdp), snapshotHash: null };
                newCascades.set(id, cascade);
                console.log(`✨ Added cascade: ${meta.chatTitle}`);
            } else { cdp.socket.destroy(); }
        } catch (e) { /* console.error(e.message) */ }
    }

    for (const [id, c] of cascades.entries()) {
        if (!newCascades.has(id)) { console.log(`👋 Removing: ${c.metadata.chatTitle}`); try { c.cdp.socket.destroy(); } catch { } }
    }
    const changed = cascades.size !== newCascades.size;
    cascades = newCascades;
    if (changed) broadcastCascadeList();
}

async function updateSnapshots() {
    await Promise.all(Array.from(cascades.values()).map(async (c) => {
        try {
            const snap = await captureHTML(c.cdp);
            if (snap) {
                const hash = hashString(snap.html);
                if (hash !== c.snapshotHash) { c.snapshot = snap; c.snapshotHash = hash; wsBroadcast({ type: 'snapshot_update', cascadeId: c.id }); }
            }
        } catch { }
    }));
}

function broadcastCascadeList() {
    wsBroadcast({ type: 'cascade_list', cascades: Array.from(cascades.values()).map(c => ({ id: c.id, title: c.metadata.chatTitle, window: c.metadata.windowTitle, active: c.metadata.isActive })) });
}

// --- HTTP Server ---
const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');

    const json = (data, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
    const notFound = () => json({ error: 'Not found' }, 404);

    if (req.method === 'GET' && pathname === '/cascades') {
        return json(Array.from(cascades.values()).map(c => ({ id: c.id, title: c.metadata.chatTitle, active: c.metadata.isActive })));
    }

    const snapMatch = pathname.match(/^\/snapshot\/(.+)$/);
    if (req.method === 'GET' && snapMatch) {
        const c = cascades.get(snapMatch[1]);
        if (!c || !c.snapshot) return notFound();
        return json(c.snapshot);
    }

    if (req.method === 'GET' && pathname === '/snapshot') {
        const active = Array.from(cascades.values()).find(c => c.metadata.isActive) || cascades.values().next().value;
        if (!active || !active.snapshot) return json({ error: 'No snapshot' }, 503);
        return json(active.snapshot);
    }

    const styleMatch = pathname.match(/^\/styles\/(.+)$/);
    if (req.method === 'GET' && styleMatch) {
        const c = cascades.get(styleMatch[1]);
        if (!c) return notFound();
        return json({ css: c.css || '' });
    }

    const sendMatch = pathname.match(/^\/send\/(.+)$/);
    if (req.method === 'POST' && sendMatch) {
        const c = cascades.get(sendMatch[1]);
        if (!c) return notFound();
        let body = '';
        req.on('data', d => body += d);
        req.on('end', async () => {
            try {
                const { message } = JSON.parse(body);
                console.log(`Message to ${c.metadata.chatTitle}: ${message}`);
                const result = await injectMessage(c.cdp, message);
                if (result.ok) json({ success: true }); else json(result, 500);
            } catch (e) { json({ error: e.message }, 500); }
        });
        return;
    }

    // Static files
    let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
    fs.stat(filePath, (err, stat) => {
        if (err || !stat.isFile()) { filePath = path.join(__dirname, 'public', 'index.html'); }
        fs.readFile(filePath, (err2, data) => {
            if (err2) { res.writeHead(404); res.end('Not found'); return; }
            const ext = path.extname(filePath);
            res.writeHead(200, { 'Content-Type': getMime(ext) });
            res.end(data);
        });
    });
});

// --- WebSocket Upgrade ---
server.on('upgrade', (req, socket, head) => {
    if (req.headers['upgrade']?.toLowerCase() !== 'websocket') { socket.destroy(); return; }
    wsHandshake(req, socket);
    wsClients.add(socket);
    let buf = Buffer.alloc(0);

    socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 2) {
            const sz = frameSize(buf);
            if (buf.length < sz) break;
            const frame = wsDecodeFrame(buf);
            buf = buf.slice(sz);
            if (!frame) break;
            if (frame.opcode === 8) { socket.destroy(); wsClients.delete(socket); break; }
            if (frame.opcode === 9) { // ping -> pong
                const pong = Buffer.alloc(2); pong[0] = 0x8a; pong[1] = 0; socket.write(pong);
            }
        }
    });

    socket.on('close', () => wsClients.delete(socket));
    socket.on('error', () => { wsClients.delete(socket); socket.destroy(); });

    // Send cascade list immediately
    const list = Array.from(cascades.values()).map(c => ({ id: c.id, title: c.metadata.chatTitle, window: c.metadata.windowTitle, active: c.metadata.isActive }));
    try { socket.write(wsEncodeFrame(JSON.stringify({ type: 'cascade_list', cascades: list }))); } catch { }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    discover();
    setInterval(discover, DISCOVERY_INTERVAL);
    setInterval(updateSnapshots, POLL_INTERVAL);
});
