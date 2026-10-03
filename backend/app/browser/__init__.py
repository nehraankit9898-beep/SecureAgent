"""Phase 09 — Browser Agent (policy-gated, provider-neutral).

The browser subsystem follows the same non-negotiable rule as every other
computer action: the LLM never touches a browser API directly. The model can
only ask for a named tool (``browser_navigate``, ``browser_click``, ...), and
every tool call passes

    schema validation -> permissions -> risk/approval policy -> URL/network
    policy (DNS-pinned SSRF checks + Control Center allow/block lists) ->
    the browser engine -> output validation -> untrusted-content wrapping ->
    audit.

Key properties:
* ``BrowserEngine`` is an interface: the real implementation drives Playwright
  (``PlaywrightEngine``); tests and embedding applications inject their own
  engine. Engine absence is reported honestly (``BROWSER_ENGINE_UNAVAILABLE``)
  and fails closed — no silent fallback to a different browser.
* Page content is ALWAYS untrusted data: it is wrapped with
  ``security.untrusted_context`` before it can reach a prompt, and pages can
  never change SecureAgent policy.
* Sensitive actions (purchase / send message / submit form / delete / account
  or security change / credential operation) require an explicit approval on
  top of the ordinary tool approval.
* Cookies, session storage and Authorization headers never leave the browser
  context: they are never returned to the model, never logged, never stored.
"""

from app.browser.policy import (SENSITIVE_ACTIONS, BrowserPolicy,
                                BrowserPolicyError)
from app.browser.provider import (BrowserEngine, BrowserEngineUnavailable,
                                  PlaywrightBrowserEngine, probe_browser_engine)
from app.browser.runtime import (BrowserRuntime, get_browser_runtime,
                                 set_browser_runtime)
from app.browser.session import BrowserSession

__all__ = [
    "SENSITIVE_ACTIONS", "BrowserPolicy", "BrowserPolicyError",
    "BrowserEngine", "BrowserEngineUnavailable", "PlaywrightBrowserEngine",
    "probe_browser_engine", "BrowserRuntime", "get_browser_runtime",
    "set_browser_runtime", "BrowserSession",
]
