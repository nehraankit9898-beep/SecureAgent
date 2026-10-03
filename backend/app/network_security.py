"""DNS-pinned, fail-closed HTTP client for untrusted destinations.

SSRF defences (spec section 9):

* Cloud metadata endpoints (169.254.169.254, fd00:ec2::254, GCP, Azure)
  are always blocked unless ``allow_cloud_metadata`` is explicitly set.
* Loopback (127.0.0.0/8, ::1) requires ``allow_local``.
* Private LAN (RFC 1918, ULA) requires ``allow_private``.
* External (everything else) requires ``allow_external``.
* Link-local, multicast, unspecified, and reserved addresses are always
  blocked.
* Mixed-trust DNS answers (one safe + one unsafe) are rejected — we
  never pick a safe answer from an unsafe set.
"""
from __future__ import annotations
import asyncio, ipaddress, socket
from dataclasses import dataclass
from urllib.parse import urljoin,urlsplit,urlunsplit
import httpx
from app.control_center import get_control_center
class NetworkPolicyError(ValueError): code="NETWORK_POLICY_BLOCKED"
@dataclass(frozen=True)
class ValidatedTarget:
 original_url:str; connect_url:str; host_header:str; sni_hostname:str; addresses:tuple[str,...]

# Cloud metadata endpoints that must be blocked by default to prevent SSRF.
CLOUD_METADATA_ENDPOINTS = (
    ipaddress.ip_network('169.254.169.254/32'),    # AWS / GCP / OpenStack metadata
    ipaddress.ip_network('fd00:ec2::254/128'),      # AWS IMDSv6
    ipaddress.ip_network('100.100.100.200/32'),     # Alibaba Cloud metadata
    ipaddress.ip_network('90.84.40.0/24'),           # OVH metadata (subset)
)

def _is_cloud_metadata(a: ipaddress._BaseAddress) -> bool:
    return any(a in net for net in CLOUD_METADATA_ENDPOINTS)

def _special(a):
    """Always-blocked addresses: link-local, multicast, unspecified,
    reserved, and cloud metadata endpoints."""
    return (a.is_link_local or a.is_multicast or a.is_unspecified
            or a.is_reserved or _is_cloud_metadata(a))
async def resolve_target(url,*,allow_local=False,allow_private=False,allow_external=True,allow_dns=True):
 q=urlsplit(url)
 if q.scheme not in {'http','https'} or not q.hostname or q.username or q.password: raise NetworkPolicyError('invalid HTTP(S) network URL')
 try: port=q.port
 except ValueError as e: raise NetworkPolicyError('invalid network port') from e
 try: addrs=[ipaddress.ip_address(q.hostname)]
 except ValueError:
  if not allow_dns: raise NetworkPolicyError('DNS hostnames are disabled by Network settings')
  try: rows=await asyncio.get_running_loop().getaddrinfo(q.hostname,port or (443 if q.scheme=='https' else 80),type=socket.SOCK_STREAM)
  except OSError as e: raise NetworkPolicyError('network host could not be resolved') from e
  addrs=[]
  for row in rows:
   a=ipaddress.ip_address(row[4][0]); addrs += [] if a in addrs else [a]
 if not addrs or any(_special(a) for a in addrs): raise NetworkPolicyError('metadata and special-use targets are blocked')
 if any(a.is_loopback for a in addrs) and not allow_local: raise NetworkPolicyError('localhost is disabled by Network settings')
 if any(a.is_private and not a.is_loopback for a in addrs) and not allow_private: raise NetworkPolicyError('private LAN targets are disabled by Network settings')
 if any(not a.is_private and not a.is_loopback for a in addrs) and not allow_external: raise NetworkPolicyError('external network targets are disabled by Network settings')
 # Reject mixed-trust answers; never select a safe answer from an unsafe set.
 chosen=addrs[0]; host=f'[{chosen}]' if chosen.version==6 else str(chosen); port_suffix=f':{port}' if port else ''
 connect=urlunsplit((q.scheme,host+port_suffix,q.path,q.query,'')); default=(q.scheme=='https' and port in (None,443)) or (q.scheme=='http' and port in (None,80))
 host_header=q.hostname if default else f'{q.hostname}:{port}'
 return ValidatedTarget(url,connect,host_header,q.hostname,tuple(str(a) for a in addrs))
async def validate_url(url,**kw):
 return await resolve_target(url,**kw)
@dataclass
class SafeHttpClient:
 timeout:float; max_bytes:int; allow_local:bool=False; allow_private:bool=False; allow_external:bool=True; allow_dns:bool=True; max_redirects:int=3
 async def request(self,method,url,*,params=None,json_body=None):
  # Control Center NETWORK master gate (spec section 8): the runtime network
  # mode decides whether ANY tool HTTP traffic may leave. This is the single
  # choke point behind web_search, http_request, and network diagnostics, so
  # a Network master switch turned OFF blocks everything deterministically
  # and records telemetry for the Control Center UI.
  try:
   gate=get_control_center()
  except Exception as error:
   raise NetworkPolicyError(
    'NETWORK_RUNTIME_POLICY_UNAVAILABLE: network access is blocked because '
    'the Control Center policy could not be loaded'
   ) from error
  if gate is None:
   raise NetworkPolicyError(
    'NETWORK_RUNTIME_POLICY_UNAVAILABLE: network access is blocked because '
    'the Control Center policy is unavailable'
   )
  from urllib.parse import urlsplit as _urlsplit
  gate.check_network(_urlsplit(url).hostname or url)
  current=url
  async with httpx.AsyncClient(timeout=self.timeout,follow_redirects=False,trust_env=False) as client:
   for _ in range(self.max_redirects+1):
    target=await validate_url(current,allow_local=self.allow_local,allow_private=self.allow_private,allow_external=self.allow_external,allow_dns=self.allow_dns)
    # Resolve once, validate every returned address, and connect to the selected
    # numeric address.  Using the original hostname here would perform a second
    # DNS lookup inside httpx and reopen a DNS-rebinding/TOCTOU window.
    if isinstance(target,str):  # compatibility for injected test validators
     q=urlsplit(target)
     target=ValidatedTarget(target,target,q.netloc,q.hostname or '',())
    headers={'Host':target.host_header}
    extensions={'sni_hostname':target.sni_hostname.encode()} if urlsplit(current).scheme=='https' else None
    async with client.stream(method,target.connect_url,params=params,json=json_body,headers=headers,extensions=extensions) as response:
     if response.is_redirect:
      location=response.headers.get('location')
      if not location: raise NetworkPolicyError('redirect omitted its destination')
      current=urljoin(current,location);params={};json_body=None;continue
     response.raise_for_status(); declared=response.headers.get('content-length')
     if declared:
      try: n=int(declared)
      except (TypeError,ValueError) as e: raise NetworkPolicyError('network response supplied an invalid content length') from e
      if n<0: raise NetworkPolicyError('network response supplied an invalid content length')
      if n>self.max_bytes: raise NetworkPolicyError('network response exceeds size limit')
     chunks=[];size=0
     async for chunk in response.aiter_bytes():
      size+=len(chunk)
      if size>self.max_bytes: raise NetworkPolicyError('network response exceeds size limit')
      chunks.append(chunk)
     return response.status_code,response.headers.get('content-type',''),b''.join(chunks).decode('utf-8','replace')
  raise NetworkPolicyError('too many network redirects')
 async def get_json(self,url,*,params):
  import json
  _,_,text=await self.request('GET',url,params=params)
  try: value=json.loads(text)
  except (ValueError,UnicodeError) as e: raise NetworkPolicyError('network provider returned invalid JSON') from e
  if not isinstance(value,dict): raise NetworkPolicyError('network provider returned an invalid response')
  return value
