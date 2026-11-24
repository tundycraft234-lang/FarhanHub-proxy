// Serves files published from the Farhan Hub Dev Panel to every visitor.
// When a file has no published edit, the original static file is served.
// Escape hatch: visit any page with ?fh-safe=1 to ignore all edits (?fh-safe=0 to turn it off).
import type { Config, Context } from '@netlify/edge-functions'
import { getStore } from '@netlify/blobs'

type Manifest = { files: Record<string, { v: string; updatedAt: number }> }

const CONTENT_TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8',
}

const PRETTY: Record<string, string> = { '/': '/index.html', '/index': '/index.html', '/NT': '/NT.html' }

// Short in-memory cache so most requests skip the Blobs lookup.
const MANIFEST_TTL_MS = 3000
const memo: { manifest: Manifest | null; at: number; files: Map<string, string> } = {
  manifest: null,
  at: 0,
  files: new Map(),
}

function store() {
  return getStore({ name: 'fh-site-files', consistency: 'strong' })
}

async function getManifest(): Promise<Manifest> {
  if (memo.manifest && Date.now() - memo.at < MANIFEST_TTL_MS) return memo.manifest
  const manifest = ((await store().get('__manifest.json', { type: 'json' })) as Manifest | null) ?? { files: {} }
  memo.manifest = manifest
  memo.at = Date.now()
  return manifest
}

async function getFile(key: string, version: string): Promise<string | null> {
  const cacheKey = `${key}@${version}`
  const hit = memo.files.get(cacheKey)
  if (hit !== undefined) return hit
  const content = (await store().get(key, { type: 'text' })) as string | null
  if (content !== null) {
    for (const k of memo.files.keys()) if (k.startsWith(`${key}@`)) memo.files.delete(k)
    memo.files.set(cacheKey, content)
  }
  return content
}

export default async (req: Request, context: Context) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return

  const url = new URL(req.url)
  const safeParam = url.searchParams.get('fh-safe')
  if (safeParam === '1') context.cookies.set({ name: 'fh_safe', value: '1', path: '/', sameSite: 'Lax' })
  if (safeParam === '0') context.cookies.delete({ name: 'fh_safe', path: '/' })
  const safe = safeParam === '1' || (safeParam !== '0' && context.cookies.get('fh_safe') === '1')

  if (safe || url.searchParams.has('fh-original')) return

  const path = PRETTY[url.pathname] ?? url.pathname
  const key = decodeURIComponent(path).replace(/^\/+/, '')

  const manifest = await getManifest()
  const entry = manifest.files?.[key]
  if (!entry) return

  const content = await getFile(key, entry.v)
  if (content === null) return

  const ext = key.split('.').pop() ?? ''
  return new Response(req.method === 'HEAD' ? null : content, {
    headers: {
      'content-type': CONTENT_TYPES[ext] ?? 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=0, must-revalidate',
      'x-fh-live': entry.v,
    },
  })
}

export const config: Config = {
  path: ['/', '/index', '/index.html', '/NT', '/NT.html', '/style.css', '/script.js', '/fh-live.json', '/fh/*'],
  onError: 'bypass',
}
