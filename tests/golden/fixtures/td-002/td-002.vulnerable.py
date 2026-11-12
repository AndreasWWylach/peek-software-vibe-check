from openai import OpenAI

client = OpenAI()


def ask(question: str) -> str:
    chat = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
        # No max_tokens — unbounded output.
    )
    return chat.choices[0].message.content
