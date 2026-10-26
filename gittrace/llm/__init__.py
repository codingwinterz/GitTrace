"""
gittrace.llm — the model layer (LiteLLM; a local Ollama model by default).

The rules decide what is a finding. The model only comments on findings the
rules already produced: a verdict, a reason, a bounded severity adjustment
and an optional fix, which GitTrace turns into a diff and checks but never
applies.

    client   one structured call: model choice, options, schema validation, one retry
    schemas  the pydantic schema each task's reply must match
    prompts  the instructions, and the fence around untrusted scanned code
    context  what the model sees about one finding, within a token budget
    cache    replies on disk (.gittrace/cache), keyed by model, prompt version and input
    fix      a suggested replacement -> unified diff, checked with `git apply --check`
    triage   all of the above, per finding
"""
