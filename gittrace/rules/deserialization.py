"""
GT-DESER-001 — unsafe deserialization.

Matches, when the data argument is not a constant:
  - pickle.load / pickle.loads (also cPickle, _pickle, dill), pandas.read_pickle;
  - marshal.load / marshal.loads;
  - yaml.load / yaml.load_all unless the loader (Loader= or the second
    positional argument) is yaml.SafeLoader or yaml.CSafeLoader;
  - yaml.unsafe_load / yaml.unsafe_load_all.

Not findings: yaml.safe_load, yaml.load(..., Loader=SafeLoader), json.
"""

from __future__ import annotations

from gittrace.languages.base import CallSite
from gittrace.rules.base import Match, Rule, last_name

PICKLE_LIKE = frozenset({
    f"{module}.{fn}"
    for module in ("pickle", "cPickle", "_pickle", "dill", "marshal")
    for fn in ("load", "loads")
} | {"pandas.read_pickle"})
YAML_LOAD = frozenset({"yaml.load", "yaml.load_all"})
YAML_UNSAFE = frozenset({"yaml.unsafe_load", "yaml.unsafe_load_all"})
SAFE_LOADERS = frozenset({"SafeLoader", "CSafeLoader"})


class UnsafeDeserialization(Rule):
    rule_id = "GT-DESER-001"
    category = "unsafe-deserialization"
    title = "Unsafe deserialization"
    base_severity = "high"

    def check_call(self, call: CallSite) -> Match | None:
        evidence: tuple[str, ...] = ()
        if call.dotted in YAML_LOAD:
            loader = call.argument(1, "Loader")
            if loader is not None and loader.ref and last_name(loader.ref) in SAFE_LOADERS:
                return None
            evidence = (f"Loader={loader.text}" if loader is not None else "no Loader (unsafe default)",)
        elif call.dotted not in PICKLE_LIKE and call.dotted not in YAML_UNSAFE:
            return None
        data = call.argument(0, "stream", "data", "file", "filepath_or_buffer")
        if data is None or data.is_literal:
            return None
        return self.match_call(
            call, f"`{call.dotted}` can run code from the data it loads.", data, evidence,
        )
