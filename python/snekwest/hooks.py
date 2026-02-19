"""
snekwest.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the hooks system.

Available hooks:

``pre_request``:
    Called after prepare_request() in Session.request(), before sending.
    The hook receives the PreparedRequest as hook_data.

``pre_send``:
    Called in Session.send() just before the adapter sends the request.
    The hook receives the PreparedRequest as hook_data.

``response``:
    The response generated from a Request.

``on_redirect``:
    Called during redirect resolution, after each intermediate response.
    The hook receives the Response as hook_data.

``on_error``:
    Called when adapter.send() raises an exception.
    The hook receives the exception as hook_data.
    If the hook returns a non-None value, it is used as the response
    instead of re-raising the exception.
"""

HOOKS = ["pre_request", "pre_send", "response", "on_redirect", "on_error"]


def default_hooks():
    return {event: [] for event in HOOKS}


def dispatch_hook(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data
