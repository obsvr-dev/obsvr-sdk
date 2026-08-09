"""Real Haystack scheduler coverage for the prompt guard's terminal branch."""

import asyncio
import unittest
from unittest.mock import patch

import obsvr

try:
    from haystack import Pipeline, component

    from obsvr.integrations.haystack import ObsvrGuard

    _HAS_HAYSTACK = True
except ImportError:
    _HAS_HAYSTACK = False


if _HAS_HAYSTACK:

    @component
    class _RecordingGenerator:
        def __init__(self) -> None:
            self.sync_prompts = []
            self.async_prompts = []

        @component.output_types(reply=str)
        def run(self, prompt: str):
            self.sync_prompts.append(prompt)
            return {"reply": "generated"}

        @component.output_types(reply=str)
        async def run_async(self, prompt: str):
            self.async_prompts.append(prompt)
            return {"reply": "generated"}


@unittest.skipUnless(_HAS_HAYSTACK, "haystack-ai is not installed")
class TestRealHaystackPromptPrivacy(unittest.TestCase):
    def setUp(self) -> None:
        obsvr._reset()

    def tearDown(self) -> None:
        obsvr._reset()

    @staticmethod
    def _pipeline():
        generator = _RecordingGenerator()
        pipeline = Pipeline()
        pipeline.add_component("guard", ObsvrGuard())
        pipeline.add_component("generator", generator)
        pipeline.connect("guard.prompt", "generator.prompt")
        return pipeline, generator

    @staticmethod
    def _init_blocking_policy() -> None:
        obsvr.init(
            api_key="test",
            ingest_url="http://localhost:9",
            policy_refresh_interval_s=0,
            on_pre_call=lambda _event: "block",
        )

    @staticmethod
    def _init_allowing_policy() -> None:
        obsvr.init(
            api_key="test",
            ingest_url="http://localhost:9",
            policy_refresh_interval_s=0,
        )

    def test_sync_block_is_terminal_without_error_snapshot_or_prompt_output(
        self,
    ) -> None:
        raw_prompt = "sync-private-prompt-123-45-6789"
        self._init_blocking_policy()
        pipeline, generator = self._pipeline()

        with patch("obsvr.integrations.haystack.emit_event"):
            result = pipeline.run({"guard": {"prompt": raw_prompt}})

        self.assertEqual(generator.sync_prompts, [])
        self.assertEqual(
            result,
            {
                "guard": {
                    "blocked": True,
                    "redacted": False,
                    "block_reason": "policy_blocked",
                }
            },
        )
        self.assertNotIn(raw_prompt, repr(result))

        # Paired control proves the graph really can reach this generator.
        obsvr._reset()
        self._init_allowing_policy()
        with patch("obsvr.integrations.haystack.emit_event"):
            pipeline.run({"guard": {"prompt": "safe sync prompt"}})
        self.assertEqual(generator.sync_prompts, ["safe sync prompt"])

    def test_async_block_is_terminal_without_error_snapshot_or_prompt_output(
        self,
    ) -> None:
        if not hasattr(Pipeline, "run_async"):
            self.skipTest("this Haystack release has no asynchronous Pipeline API")
        raw_prompt = "async-private-prompt-123-45-6789"
        self._init_blocking_policy()
        pipeline, generator = self._pipeline()

        with patch("obsvr.integrations.haystack.emit_event"):
            result = asyncio.run(pipeline.run_async({"guard": {"prompt": raw_prompt}}))

        self.assertEqual(generator.sync_prompts, [])
        self.assertEqual(generator.async_prompts, [])
        self.assertEqual(
            result,
            {
                "guard": {
                    "blocked": True,
                    "redacted": False,
                    "block_reason": "policy_blocked",
                }
            },
        )
        self.assertNotIn(raw_prompt, repr(result))

        # Paired control proves the async scheduler really can reach the sink.
        obsvr._reset()
        self._init_allowing_policy()
        with patch("obsvr.integrations.haystack.emit_event"):
            asyncio.run(pipeline.run_async({"guard": {"prompt": "safe async prompt"}}))
        self.assertEqual(generator.async_prompts, ["safe async prompt"])


if __name__ == "__main__":
    unittest.main()
