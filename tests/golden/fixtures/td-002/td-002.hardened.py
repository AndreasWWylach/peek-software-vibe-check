from openai import OpenAI

client = OpenAI()


def ask(question: str) -> str:
    chat = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=500,
        messages=[{"role": "user", "content": question[:2000]}],
    )
    return chat.choices[0].message.content
