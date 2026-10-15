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

if (!ACCOUNT_ID || !API_KEY) {
  console.error('Missing CLOUDFLARE_ACCOUNT_ID and/or CLOUDFLARE_API_KEY')
  process.exit(2)
}

const MODELS = [
  '@cf/mistralai/mistral-small-3.1-24b-instruct', // control: current model, known to fail
  '@cf/meta/llama-3.1-8b-instruct', // primary candidate
  '@cf/meta/llama-3.3-70b-instruct-fp8-fast', // fallback candidate
]

const ENDPOINT = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/ai/v1/chat/completions`

const PROMPT =
  'In one sentence, describe what a binary reverse engineering tool does. ' +
  'Do not use any numbers or lists.'

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
      max_tokens: 64,
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

  results.push({ model, runs: RUNS, bad, errors, totalChunks, samples })
  const verdict = errors > 0 ? 'ERRORS' : bad === 0 ? 'CLEAN' : 'FLAKY'
  const line = `${model}: ${verdict} (${bad}/${RUNS - errors} runs emitted numeric content, ${errors}/${RUNS} errored, ${totalChunks} chunks)`
  console.log(line)
  summary += `- ${line}\n`
}

console.log('=== JSON ===')
console.log(JSON.stringify(results, null, 2))

require('fs').appendFileSync(
  process.env.GITHUB_STEP_SUMMARY,
  '## Workers AI stream probe\n\n' + summary + '\n```json\n' + JSON.stringify(results, null, 2) + '\n```\n',
)