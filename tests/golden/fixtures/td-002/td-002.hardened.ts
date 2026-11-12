import { NextResponse } from 'next/server'
import { OpenAI } from 'openai'
import { rateLimit } from '@/lib/rate-limit' // per-user/IP limiter
import { getSession } from '@/lib/auth' // require login

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

export async function POST(req: Request) {
  const session = await getSession()
  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })

  if (!(await rateLimit(session.userId, 20, 60))) {
    return NextResponse.json({ error: 'rate_limited' }, { status: 429 })
  }

  const { question } = await req.json()

  const chat = await openai.chat.completions.create({
    model: 'gpt-4o-mini', // cheapest model that fits the job
    max_tokens: 500, // hard output cap
    messages: [{ role: 'user', content: question.slice(0, 2000) }],
  })

  return NextResponse.json({ answer: chat.choices[0].message.content })
}
