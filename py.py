import cohere

co = cohere.Client("REDACTED_COHERE_KEY")

response = co.chat(
    model="command-xlarge-nightly",
    message="What is the capital of France?"
)

print(response.text)