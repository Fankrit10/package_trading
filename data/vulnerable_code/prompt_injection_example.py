from openai import OpenAI


client = OpenAI()


def chat_with_ai(user_input: str):
    """
    Vulnerable LLM integration that doesn't sanitize user input.
    Allows prompt injection attacks.
    """
    system_prompt = "You are a helpful assistant. Only answer questions about products."

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]
    )

    return response.choices[0].message.content


def generate_report(user_data: str):
    """
    Another prompt injection vulnerability in report generation.
    """
    prompt = f"Generate a financial report based on this data: {user_data}"

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )

    return response.choices[0].message.content
