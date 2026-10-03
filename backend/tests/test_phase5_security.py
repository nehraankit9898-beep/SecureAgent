import asyncio,ipaddress,pytest
from app.network_security import resolve_target,NetworkPolicyError
@pytest.mark.asyncio
async def test_dns_pinning_and_multiple_answer_rejection(monkeypatch):
 async def answers(*a,**k): return [(2,1,6,'',('93.184.216.34',443))]
 monkeypatch.setattr(asyncio.get_running_loop(),'getaddrinfo',answers)
 t=await resolve_target('https://example.test/x');assert t.connect_url.startswith('https://93.184.216.34/') and t.sni_hostname=='example.test'
@pytest.mark.asyncio
@pytest.mark.parametrize('url',['http://127.0.0.1','http://10.0.0.1','http://169.254.1.1','http://[::1]','http://[fe80::1]'])
async def test_special_targets_rejected(url):
 with pytest.raises(NetworkPolicyError):await resolve_target(url)
