import cohere

co = cohere.Client("pc5OuQ6F4KuhIk9OIJTUkgLDSwaJfagP404swBXM")

response = co.chat(
    model="command-xlarge-nightly",
    message="What is the capital of France?"
)

print(response.text)