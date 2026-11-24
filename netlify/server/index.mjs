// Farhan Hub API — AI assistant + PIN-protected live site editor.
// Static proxy files are untouched; edits are stored in Netlify Blobs and
// served to every visitor by netlify/edge-functions/live-files.ts.
import { Hono } from 'hono'
import { getStore } from '@netlify/blobs'
import Anthropic from '@anthropic-ai/sdk'
import { scryptSync, timingSafeEqual, createHash } from 'node:crypto'

export const config = { path: '/api/*' }

const anthropic = new Anthropic()
const app = new Hono()

// ---------------------------------------------------------------------------
// Editable files (keys match the URL path without the leading slash)
// ---------------------------------------------------------------------------
export const EDITABLE = {
  'fh-live.json': 'Live theme & custom code',
  'index.html': 'Browser shell (index.html)',
  'style.css': 'Browser styles (style.css)',
  'script.js': 'Browser logic (script.js)',
  'NT.html': 'New tab page (NT.html)',
  'fh/theme.css': 'Neon theme (fh/theme.css)',
  'fh/nt.css': 'New tab theme (fh/nt.css)',
  'fh/fx.js': 'Cursor & background FX (fh/fx.js)',
  'fh/assistant.js': 'AI assistant (fh/assistant.js)',
}
const MANIFEST_KEY = '__manifest.json'
const MAX_FILE_BYTES = 1024 * 1024

const files = () => getStore({ name: 'fh-site-files', consistency: 'strong' })
const security = () => getStore({ name: 'fh-security', consistency: 'strong' })

// ---------------------------------------------------------------------------
// PIN check. Set the DEV_PIN environment variable to change the PIN; otherwise
// the built-in PIN is checked against this slow scrypt hash (never plain text).
// ---------------------------------------------------------------------------
const PIN_SALT = 'c3d72b4c42aaa3cad4cf5a9ee4124fa5'
const PIN_HASH = '57c8b21ebda58606640e1057e1905d6d33960386968278e1fbce8ab67c8e933b'
const SCRYPT = { N: 65536, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }
let lastGoodPin = null

function pinMatches(pin) {
  if (typeof pin !== 'string' || pin.length === 0 || pin.length > 128) return false
  if (lastGoodPin !== null && pin === lastGoodPin) return true
  let ok
  if (process.env.DEV_PIN) {
    const a = createHash('sha256').update(pin).digest()
    const b = createHash('sha256').update(process.env.DEV_PIN).digest()
    ok = timingSafeEqual(a, b)
  } else {
    const h = scryptSync(pin, PIN_SALT, 32, SCRYPT)
    ok = timingSafeEqual(h, Buffer.from(PIN_HASH, 'hex'))
  }
  if (ok) lastGoodPin = pin
  return ok
}

// Global lockout: 8 wrong PINs inside 10 minutes locks the editor for the rest of the window.
const LOCK_WINDOW_MS = 10 * 60 * 1000
const LOCK_MAX_FAILS = 8

async function checkPin(pin) {
  const store = security()
  const guard = (await store.get('pin-guard', { type: 'json' })) ?? { fails: [] }
  const now = Date.now()
  const recent = (guard.fails ?? []).filter((t) => now - t < LOCK_WINDOW_MS)
  if (recent.length >= LOCK_MAX_FAILS) {
    const retryIn = Math.ceil((recent[0] + LOCK_WINDOW_MS - now) / 1000)
    return { ok: false, status: 429, error: `Too many wrong PINs. Try again in ${retryIn}s.` }
  }
  if (pinMatches(pin)) {
    if (recent.length) await store.setJSON('pin-guard', { fails: [] })
    return { ok: true }
  }
  recent.push(now)
  await store.setJSON('pin-guard', { fails: recent })
  return { ok: false, status: 401, error: 'Wrong PIN' }
}

app.use('/api/admin/*', async (c, next) => {
  const result = await checkPin(c.req.header('x-fh-pin'))
  if (!result.ok) return c.json({ error: result.error }, result.status)
  await next()
})

// ---------------------------------------------------------------------------
// Admin: files
// ---------------------------------------------------------------------------
const normalizePath = (p) => String(p ?? '').replace(/^\/+/, '')

async function readManifest() {
  return (await files().get(MANIFEST_KEY, { type: 'json' })) ?? { files: {} }
}

app.post('/api/admin/login', (c) => c.json({ ok: true }))

app.get('/api/admin/files', async (c) => {
  const manifest = await readManifest()
  return c.json({
    files: Object.entries(EDITABLE).map(([path, label]) => ({
      path,
      label,
      overridden: Boolean(manifest.files[path]),
      updatedAt: manifest.files[path]?.updatedAt ?? null,
    })),
  })
})

app.get('/api/admin/file', async (c) => {
  const path = normalizePath(c.req.query('path'))
  if (!EDITABLE[path]) return c.json({ error: 'Not an editable file' }, 400)
  const content = await files().get(path, { type: 'text' })
  return c.json({ path, content, overridden: content !== null })
})

app.put('/api/admin/file', async (c) => {
  const body = await c.req.json().catch(() => null)
  const path = normalizePath(body?.path)
  if (!EDITABLE[path]) return c.json({ error: 'Not an editable file' }, 400)
  if (typeof body.content !== 'string') return c.json({ error: 'Missing content' }, 400)
  if (Buffer.byteLength(body.content) > MAX_FILE_BYTES) return c.json({ error: 'File too large (1 MB max)' }, 413)
  if (path.endsWith('.json')) {
    try { JSON.parse(body.content) } catch { return c.json({ error: 'Invalid JSON' }, 400) }
  }
  const store = files()
  await store.set(path, body.content)
  const manifest = await readManifest()
  const updatedAt = Date.now()
  manifest.files[path] = { v: updatedAt.toString(36), updatedAt }
  await store.setJSON(MANIFEST_KEY, manifest)
  return c.json({ ok: true, path, updatedAt })
})

app.delete('/api/admin/file', async (c) => {
  const path = normalizePath(c.req.query('path'))
  if (!EDITABLE[path]) return c.json({ error: 'Not an editable file' }, 400)
  const store = files()
  const manifest = await readManifest()
  delete manifest.files[path]
  await store.setJSON(MANIFEST_KEY, manifest)
  await store.delete(path)
  return c.json({ ok: true, path })
})

// ---------------------------------------------------------------------------
// Streaming helper
// ---------------------------------------------------------------------------
function streamText(iterableFactory) {
  const encoder = new TextEncoder()
  return new Response(
    new ReadableStream({
      async start(controller) {
        try {
          for await (const event of await iterableFactory()) {
            if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
              controller.enqueue(encoder.encode(event.delta.text))
            }
          }
        } catch (err) {
          console.error('AI stream error', err)
          controller.enqueue(encoder.encode('\n\n[The AI is unavailable right now. Please try again in a moment.]'))
        }
        controller.close()
      },
    }),
    { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } },
  )
}

// Admin: ask the AI to rewrite a file
app.post('/api/admin/ai-edit', async (c) => {
  const body = await c.req.json().catch(() => null)
  const path = normalizePath(body?.path)
  const instruction = String(body?.instruction ?? '').slice(0, 4000)
  const content = String(body?.content ?? '')
  if (!EDITABLE[path] || !instruction) return c.json({ error: 'Missing file or instruction' }, 400)
  if (content.length > 200_000) return c.json({ error: 'File too large for AI editing' }, 413)

  return streamText(() =>
    anthropic.messages.create({
      model: 'claude-sonnet-5-5',
      max_tokens: 32000,
      stream: true,
      system:
        'You edit files of "Farhan Hub", a static web proxy site (Scramjet + BareMux + Wisp). ' +
        'Apply the requested change and reply with ONLY the complete, updated file contents — no markdown fences, ' +
        'no explanations. Keep everything you were not asked to change exactly as it is, and never break the proxy logic.' +
        (path === 'fh-live.json'
          ? ' This JSON file has the shape {"theme":{"accent","accent2","accent3","bg","font","displayFont","radius","cursor":true|false,"cursorColor","particles":true|false,"title"},"css":"","js":"","html":""}. "css" is extra CSS applied to every page, "js" is extra JavaScript run on the main page, "html" is extra HTML appended to the main page body. Return valid JSON.'
          : ''),
      messages: [
        {
          role: 'user',
          content: `File: ${path}\n\n<file>\n${content}\n</file>\n\nChange request: ${instruction}`,
        },
      ],
    }),
  )
})

// ---------------------------------------------------------------------------
// Public: AI assistant chat
// ---------------------------------------------------------------------------
app.post('/api/chat', async (c) => {
  const body = await c.req.json().catch(() => null)
  const messages = (Array.isArray(body?.messages) ? body.messages : [])
    .filter((m) => (m?.role === 'user' || m?.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
    .slice(-20)
    .map((m) => ({ role: m.role, content: m.content.slice(0, 6000) }))
  while (messages.length && messages[0].role !== 'user') messages.shift()
  if (!messages.length || messages.at(-1).role !== 'user') return c.json({ error: 'Send a message first' }, 400)

  return streamText(() =>
    anthropic.messages.create({
      model: 'claude-haiku-5-5',
      max_tokens: 1500,
      stream: true,
      system:
        'You are Farhan AI, the friendly built-in assistant of Farhan Hub (made by Tundy Team). ' +
        'Help with homework, studying, explanations, writing, coding and general questions. ' +
        'Be concise, clear and upbeat; use short paragraphs, bullet lists and Markdown code blocks when useful.',
      messages,
    }),
  )
})

app.notFound((c) => c.json({ error: 'Not found' }, 404))

export default app
