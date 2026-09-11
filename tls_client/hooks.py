"""Response hook helpers."""

HOOKS = ["response"]


def default_hooks():
    return {"response": []}


def dispatch_hook(key, hooks, hook_data, **kwargs):
    hooks = hooks or {}
    selected = hooks.get(key, [])
    if callable(selected):
        selected = [selected]
    for hook in selected:
        result = hook(hook_data, **kwargs)
        if result is not None:
            hook_data = result
    return hook_data


def merge_hooks(request_hooks, session_hooks):
    result = default_hooks()
    for source in (session_hooks or {}, request_hooks or {}):
        for key, values in source.items():
            if callable(values):
                values = [values]
            result.setdefault(key, []).extend(values or [])
    return result

