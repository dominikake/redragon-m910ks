// TEMPORARY diagnostic probe - delete after use.
//
// For each model, measures two things over the Workers AI OpenAI-compatible
// streaming endpoint:
//   1. whether any chunk carries a non-string choices[0].delta.content
//      (the bug that makes OpenCode's zod schema reject the stream), and
//   2. how many neurons a realistic review-length stream actually costs.
//
// Parses RAW SSE bytes (no SDK in the path) so we observe exactly what the
// provider sends. Neurons are read from usage.neurons on the final chunk.

const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID
const API_KEY = process.env.CLOUDFLARE_API_KEY
const RUNS = Number(process.env.RUNS || 10)
const MAX_TOKENS = Number(process.env.MAX_TOKENS || 2048)

if (!ACCOUNT_ID || !API_KEY) {
  console.error('Missing CLOUDFLARE_ACCOUNT_ID and/or CLOUDFLARE_API_KEY')
  process.exit(2)
}

const MODELS = (
  process.env.MODELS ||
  '@cf/ibm-granite/granite-4.0-h-micro,@cf/qwen/qwen3-30b-a3b-fp8,' +
    '@cf/meta/llama-3.1-8b-instruct-fp8-fast,@cf/meta/llama-3.2-3b-instruct'
).split(',')

const ENDPOINT = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/ai/v1/chat/completions`

// Output length is what drives the bug (a 64-token probe never reproduced it),
// so keep the prompt short and the generation long to stay inside the 10k
// daily free allocation while still exercising the streaming path.
const PROMPT =
  'You are reviewing a pull request that adds three offline Python helpers to ' +
  'regenerate a GUI analysis document from a vendor binary, and corrects an ' +
  'error in a FunID lookup table. The new tools are re_pe.py, re_cmds.py and ' +
  're_fn.py. Write a thorough multi-paragraph review covering correctness, ' +
  'naming consistency, and whether the documentation was updated.'

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
    return { ok: false, reason: `HTTP ${res.status}: ${body.slice(0, 200)}` }
  }

  const raw = await res.text()

  let chunks = 0
  let badChunks = 0
  let neurons = 0
  let outputTokens = 0
  const samples = []

  for (const line of raw.split('\n')) {
    if (!line.startsWith('data:')) continue
    const payload = line.slice(5).trim()
    if (!payload || payload === '[DONE]') continue

    let parsed
    try {
      parsed = JSON.parse(payload)
    } catch {
      continue
    }

    if (parsed.error) {
      return { ok: false, reason: `error frame: ${JSON.stringify(parsed.error).slice(0, 200)}` }
    }

    if (typeof parsed.usage?.neurons === 'number') neurons = parsed.usage.neurons
    if (typeof parsed.usage?.completion_tokens === 'number') outputTokens = parsed.usage.completion_tokens

    chunks++
    const content = parsed.choices?.[0]?.delta?.content
    if (content !== undefined && typeof content !== 'string') {
      badChunks++
      if (samples.length < 3) samples.push(content)
    }
  }

  return { ok: true, chunks, badChunks, neurons, outputTokens, samples }
}

const results = []
let summary = ''

for (const model of MODELS) {
  let bad = 0
  let errors = 0
  let totalChunks = 0
  let totalNeurons = 0
  let totalOutTokens = 0
  let okRuns = 0
  const samples = []
  let firstError = null

  for (let i = 0; i < RUNS; i++) {
    let r
    try {
      r = await probeOnce(model)
    } catch (err) {
      r = { ok: false, reason: String(err).slice(0, 200) }
    }

    if (!r.ok) {
      errors++
      if (!firstError) firstError = r.reason
      continue
    }

    okRuns++
    totalChunks += r.chunks
    totalNeurons += r.neurons
    totalOutTokens += r.outputTokens
    if (r.badChunks > 0) bad++
    for (const s of r.samples) if (samples.length < 3) samples.push(s)
  }

  const avgNeurons = okRuns ? totalNeurons / okRuns : null
  const verdict = errors > 0 ? 'ERRORS' : bad === 0 ? 'CLEAN' : 'FLAKY'

  results.push({
    model,
    verdict,
    runs: RUNS,
    okRuns,
    bad,
    errors,
    firstError,
    totalChunks,
    avgNeurons,
    avgOutputTokens: okRuns ? totalOutTokens / okRuns : null,
    samples,
  })

  const line =
    `${model}: ${verdict} | ${bad}/${okRuns} runs affected | ` +
    `${Math.round(totalChunks / Math.max(okRuns, 1))} chunks/run | ` +
    `${avgNeurons ? avgNeurons.toFixed(1) : 'n/a'} neurons/run` +
    (errors ? ` | first error: ${firstError}` : '')
  console.log(line)
  summary += `- ${line}\n`
}

console.log('=== JSON ===')
console.log(JSON.stringify(results, null, 2))

require('fs').appendFileSync(
  process.env.GITHUB_STEP_SUMMARY,
  '## Workers AI stream + cost probe\n\n' +
    summary +
    '\n```json\n' +
    JSON.stringify(results, null, 2) +
    '\n```\n',
)