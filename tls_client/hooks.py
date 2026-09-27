"""Response hook helpers, mirroring requests.hooks."""

from collections.abc import Mapping

HOOKS = ["response"]

__all__ = ["HOOKS", "default_hooks", "dispatch_hook", "merge_hooks", "merge_setting"]


def default_hooks():
    return {event: [] for event in HOOKS}


def dispatch_hook(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if callable(hooks):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data


def _key_val_list(value):
    if hasattr(value, "items"):
        return list(value.items())
    return list(value)


def merge_setting(request_setting, session_setting, dict_class=dict):
    """Determines the appropriate setting for a request.

    Takes into account the explicit setting on that request and the setting in
    the session.  If a setting is a dictionary, the two are merged together
    using dict_class.
    """
    if session_setting is None:
        return request_setting

    if request_setting is None:
        return session_setting

    # Bypass if not a mapping (e.g. verify)
    if not (
        isinstance(session_setting, Mapping) and isinstance(request_setting, Mapping)
    ):
        return request_setting

    merged_setting = dict_class(_key_val_list(session_setting))
    merged_setting.update(_key_val_list(request_setting))

    # Remove keys that are set to None.  Extract keys first to avoid altering
    # the dictionary during iteration.
    none_keys = [k for (k, v) in merged_setting.items() if v is None]
    for key in none_keys:
        del merged_setting[key]

    return merged_setting


def merge_hooks(request_hooks, session_hooks, dict_class=dict):
    """Properly merges both requests and session hooks.

    This is necessary because when request_hooks == {'response': []}, the merge
    breaks Session hooks entirely.
    """
    if session_hooks is None or session_hooks.get("response") == []:
        return request_hooks

    if request_hooks is None or request_hooks.get("response") == []:
        return session_hooks

    return merge_setting(request_hooks, session_hooks, dict_class)
