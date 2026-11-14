// HARDENED — the same LLM request body now carries a max_tokens cap.
const endpoint = process.env.DEEPSEEK_ENDPOINT || 'https://api.deepseek.com/chat/completions';

export async function extractEntities({ query, labels }: { query: string; labels: string[] }) {
  const body = {
    model: process.env.DEEPSEEK_MODEL || 'deepseek-chat',
    max_tokens: 500,
    messages: [
      { role: 'system', content: 'Extract entities as JSON.' },
      { role: 'user', content: JSON.stringify({ query, labels }) },
    ],
    temperature: 0,
  };
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.DEEPSEEK_API_KEY}` },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return data.choices?.[0]?.message?.content;
}
