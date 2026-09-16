"""
demo_cli.py

Run this to see the guard work end-to-end with no server, no API keys, no
external dependencies:

    python demo_cli.py

Edit SAMPLE_PROMPTS below to try your own examples.
"""

from guard import PromptGuard

SAMPLE_PROMPTS = [
    "Hi, can you draft a follow-up email to John Smith at john.smith@acme.com "
    "about his order? His phone number is 415-555-0192.",

    "Summarize this customer complaint: card number 4111 1111 1111 1111 was "
    "charged twice.",

    "Here's our internal server config: connect to 10.0.4.22 using the key "
    "sk-abcdefghijklmnopqrstuvwxyz123456.",

    "What's a good subject line for a product launch email?",

    # No PII at all, but sensitive by content — this is what the sensitivity
    # classifier catches that entity detection alone would miss.
    "Here's our internal system architecture: the customer ingestion pipeline "
    "runs through three internal services before hitting the production database.",

    # A secret that doesn't match any known vendor pattern — this is what the
    # entropy detector catches that regex patterns alone would miss.
    "Here's the deploy token: kX9pQ2vR8mN4wZ7tL1cF6hB3jY5sA0dE.",
]


def main():
    guard = PromptGuard()

    for i, prompt in enumerate(SAMPLE_PROMPTS, start=1):
        print(f"\n--- Example {i} ---")
        print(f"RAW:       {prompt}")

        result = guard.sanitize(prompt, request_id=f"demo_{i}")

        if result.blocked:
            print(f"BLOCKED:      {', '.join(result.block_reasons)}")
            print(f"SENSITIVITY:  {result.sensitivity_level}")
            continue

        print(f"SANITIZED:    {result.sanitized_prompt}")
        print(f"DETECTED:     {dict(result.entity_counts) or 'none'}")
        print(f"SENSITIVITY:  {result.sensitivity_level}")

        # Simulate an LLM response that might echo a token back
        fake_llm_response = f"Sure — here's a draft based on: {result.sanitized_prompt}"
        rehydrated = guard.rehydrate(fake_llm_response)
        print(f"REHYDRATED FOR USER: {rehydrated}")


if __name__ == "__main__":
    main()
