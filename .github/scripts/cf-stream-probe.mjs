// TEMPORARY diagnostic probe - delete after use.
//
// Checks whether Cloudflare Workers AI's OpenAI-compatible streaming endpoint
// emits a non-string choices[0].delta.content, which is what makes OpenCode's
// zod schema reject the stream and fail the PR review job.
//
// Parses the RAW SSE bytes (no SDK in the path) so we observe exactly what the
// provider sends, independent of how any client would interpret it.

const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID
const API_KEY = process.env.CLOUDFLARE_API_KEY
const RUNS = Number(process.env.RUNS || 15)
const MAX_TOKENS = Number(process.env.MAX_TOKENS || 64)

if (!ACCOUNT_ID || !API_KEY) {
  console.error('Missing CLOUDFLARE_ACCOUNT_ID and/or CLOUDFLARE_API_KEY')
  process.exit(2)
}

const MODELS = (process.env.MODELS || '@cf/mistralai/mistral-small-3.1-24b-instruct').split(',')

const ENDPOINT = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/ai/v1/chat/completions`

// Approximates the real review workload: a large PR-diff-ish prompt plus a long
// generated review. The numeric-delta bug is chunk-level, so both a big prompt
// and a long generation matter for reproducing it.
const FILLER = `tools/re_pe.py parses PE headers and emits a JSON summary of sections.
tools/re_cmds.py wraps the RE command surface and records a transcript.
tools/re_fn.py walks the import table and resolves function names.
`.repeat(60)

const PROMPT =
  'You are reviewing a pull request. Reply with a detailed review.\n\n' +
  'The pull request adds three offline helpers to regenerate analysis in docs/GUI-ANALYSIS.md from vendor/ alone. ' +
  'The pull request also corrects an error in the FunID table.\n\n' +
  'Changed files:\n' +
  FILLER +
  '\nWrite a thorough multi-paragraph review covering correctness, naming, and docs.'

async function probeOnce(model) {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      stream: true,
      max_tokens: MAX_TOKENS,
      messages: [{ role: 'user', content: PROMPT }],
    }),
  })

  if (!res.ok) {
    const body = await res.text()
    return { ok: false, reason: `HTTP ${res.status}: ${body.slice(0, 300)}` }
  }

  // Read the raw stream so nothing normalises the payload on the way in.
  const raw = await res.text()

  let chunks = 0
  let badChunks = 0
  const samples = []

  for (const line of raw.split('\n')) {
    if (!line.startsWith('data:')) continue
    const payload = line.slice(5).trim()
    if (!payload || payload === '[DONE]') continue

    let parsed
    try {
      parsed = JSON.parse(payload)
    } catch {
      continue // non-JSON keepalive/heartbeat frame
    }

    // An error frame is not a content bug, but it means the call failed.
    if (parsed.error) {
      return { ok: false, reason: `error frame: ${JSON.stringify(parsed.error).slice(0, 300)}` }
    }

    chunks++
    const content = parsed.choices?.[0]?.delta?.content
    if (content !== undefined && typeof content !== 'string') {
      badChunks++
      if (samples.length < 3) samples.push({ content, chunk: payload.slice(0, 200) })
    }
  }

  return { ok: true, chunks, badChunks, samples }
}

const results = []
let summary = ''

for (const model of MODELS) {
  let bad = 0
  let errors = 0
  let totalChunks = 0
  const samples = []

  for (let i = 0; i < RUNS; i++) {
    let r
    try {
      r = await probeOnce(model)
    } catch (err) {
      r = { ok: false, reason: String(err).slice(0, 300) }
    }

    if (!r.ok) {
      errors++
      if (samples.length === 0) samples.push({ reason: r.reason })
      continue
    }

    totalChunks += r.chunks
    if (r.badChunks > 0) bad++
    for (const s of r.samples) {
      if (samples.length < 3) samples.push(s)
    }
  }

  results.push({ model, runs: RUNS, maxTokens: MAX_TOKENS, bad, errors, totalChunks, samples })
  const verdict = errors > 0 ? 'ERRORS' : bad === 0 ? 'CLEAN' : 'FLAKY'
  const line = `${model}: ${verdict} (${bad}/${RUNS - errors} runs emitted numeric content, ${errors}/${RUNS} errored, ${totalChunks} chunks, ${Math.round(totalChunks / Math.max(RUNS - errors, 1))} chunks/run)`
  console.log(line)
  summary += `- ${line}\n`
}

console.log('=== JSON ===')
console.log(JSON.stringify(results, null, 2))

require('fs').appendFileSync(
  process.env.GITHUB_STEP_SUMMARY,
  '## Workers AI stream probe\n\n' + summary + '\n```json\n' + JSON.stringify(results, null, 2) + '\n```\n',
)