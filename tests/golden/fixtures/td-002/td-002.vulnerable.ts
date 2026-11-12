import { NextResponse } from 'next/server'
import { OpenAI } from 'openai'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

export async function POST(req: Request) {
  const { question } = await req.json()

  const chat = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: question }],
    // No max_tokens, no rate limit, no auth — anyone can call this as much as they want.
  })

  return NextResponse.json({ answer: chat.choices[0].message.content })
}
