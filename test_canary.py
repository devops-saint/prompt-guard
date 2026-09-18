"""
test_canary.py

Regression suite: run this after any change to detectors.py, classifier.py,
or policy.json to catch silently introduced false positives/negatives.

    python3 -m unittest test_canary.py -v
"""

import unittest

from guard import PromptGuard
from policy import Policy
from vault import InMemoryVault, ENTITY_PREFIX_MAP
from classifier import SensitivityClassifier


class CanaryTestCase(unittest.TestCase):
    def setUp(self):
        # Fresh guard per test so the vault doesn't leak state between cases
        self.guard = PromptGuard(
            policy=Policy.load(), vault=InMemoryVault(), classifier=SensitivityClassifier.load()
        )

    def assert_tokenizes(self, prompt: str, entity_type: str, destination: str = "any"):
        result = self.guard.sanitize(prompt, destination=destination)
        self.assertFalse(result.blocked, f"expected ALLOW, got BLOCKED: {result.block_reasons}")
        self.assertIn(entity_type, result.entity_counts, f"expected {entity_type} to be detected")
        prefix = ENTITY_PREFIX_MAP.get(entity_type, entity_type[:2].upper())
        self.assertRegex(
            result.sanitized_prompt,
            rf"\[{prefix}\d+\]",
            "expected a compact token placeholder for the detected entity in the sanitized output",
        )

    def assert_blocked(self, prompt: str, destination: str = "any"):
        result = self.guard.sanitize(prompt, destination=destination)
        self.assertTrue(result.blocked, f"expected BLOCK, got ALLOW: {result.sanitized_prompt!r}")

    def assert_allowed_unchanged(self, prompt: str, destination: str = "any"):
        result = self.guard.sanitize(prompt, destination=destination)
        self.assertFalse(result.blocked)
        self.assertEqual(result.sanitized_prompt, prompt)

    # ---- Entity detection -> tokenize ----

    def test_email_tokenized(self):
        self.assert_tokenizes("Contact me at jane.doe@example.com please", "EMAIL")

    def test_phone_tokenized(self):
        self.assert_tokenizes("Call me at 415-555-0192 tomorrow", "PHONE")

    def test_name_tokenized(self):
        self.assert_tokenizes("Please loop in Sarah Connor on this thread", "PERSON_NAME")

    # ---- Entity detection -> block ----

    def test_ssn_blocked(self):
        self.assert_blocked("My SSN is 123-45-6789")

    def test_pan_blocked(self):
        self.assert_blocked("My PAN is chfpj0322j")

    def test_credit_card_blocked(self):
        self.assert_blocked("Card: 4111 1111 1111 1111")

    def test_credit_card_invalid_luhn_not_flagged(self):
        result = self.guard.sanitize("Reference number: 1234 5678 9012 3456")
        self.assertNotIn("CREDIT_CARD", result.entity_counts)

    def test_known_api_key_pattern_blocked(self):
        self.assert_blocked("Use this key: sk-abcdefghijklmnopqrstuvwxyz123456")

    def test_aws_key_pattern_blocked(self):
        self.assert_blocked("AWS access key: AKIAABCDEFGHIJKLMNOP")

    def test_high_entropy_secret_blocked(self):
        self.assert_blocked("Here's the deploy token: kX9pQ2vR8mN4wZ7tL1cF6hB3jY5sA0dE")

    def test_ordinary_long_word_not_flagged_as_secret(self):
        self.assert_allowed_unchanged(
            "The word supercalifragilisticexpialidocious appears in the song"
        )

    def test_url_not_flagged_as_secret(self):
        self.assert_allowed_unchanged(
            "See the documentation at https://docs.example.com/guides/getting-started-here"
        )

    # ---- Sensitivity classification ----

    def test_public_prompt_allowed(self):
        self.assert_allowed_unchanged("What's a good subject line for a product launch email?")

    def test_confidential_keyword_blocks_for_public_destination(self):
        self.assert_blocked(
            "Here's our internal architecture and customer list for review", destination="any"
        )

    def test_confidential_keyword_allowed_for_approved_destination(self):
        result = self.guard.sanitize(
            "Here's our internal architecture and customer list for review",
            destination="approved_enterprise_ai",
        )
        self.assertFalse(result.blocked)
        self.assertEqual(result.sensitivity_level, "CONFIDENTIAL")

    def test_restricted_keyword_blocked_even_for_enterprise_destination(self):
        self.assert_blocked(
            "We had a security incident in the production database last night",
            destination="approved_enterprise_ai",
        )

    def test_restricted_keyword_allowed_for_restricted_destination(self):
        result = self.guard.sanitize(
            "We had a security incident in the production database last night",
            destination="approved_enterprise_ai_restricted",
        )
        self.assertFalse(result.blocked)

    def test_secret_keyword_blocked_regardless_of_destination(self):
        self.assert_blocked(
            "Here is the root password for the finance system",
            destination="approved_enterprise_ai_restricted",
        )

    # ---- Interaction: entity-level allow doesn't override sensitivity block ----

    def test_low_risk_entity_in_high_sensitivity_prompt_still_blocked(self):
        self.assert_blocked(
            "Send our pricing strategy doc to jane.doe@example.com", destination="any"
        )

    # ---- Rehydration ----

    def test_rehydration_restores_original_value(self):
        result = self.guard.sanitize("My email is jane.doe@example.com")
        fake_response = f"Sure, I'll use: {result.sanitized_prompt}"
        rehydrated = self.guard.rehydrate(fake_response)
        self.assertIn("jane.doe@example.com", rehydrated)


if __name__ == "__main__":
    unittest.main()