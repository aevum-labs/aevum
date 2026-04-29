# aevum-llm

LiteLLM-backed LLM complication for Aevum. Every call is audited: model ID, prompt hash, and response hash are recorded in the episodic ledger. Raw prompts and responses are never stored.

```bash
pip install aevum-llm
```

```python
from aevum.llm import LlmComplication
from aevum.core import Engine

engine = Engine()
engine.install_complication(
    LlmComplication(model="claude-sonnet-4-6", fallback_models=["gpt-4.1"]),
    auto_approve=True,
)
```

See the [main repository README](https://github.com/aevum-labs/aevum) for the complication installation guide.
