import json
import pytest
from app.llm import LLMError, LocalCoreProvider
from app.models import ChatRequest, Message

@pytest.mark.asyncio
async def test_local_core_plans_calculation_without_api_key():
    provider=LocalCoreProvider()
    response=await provider.chat(ChatRequest(messages=[Message(role='user',content='calculate 2+3*4')],json_mode=True))
    plan=json.loads(response.content)
    assert plan['steps'][0]['tool']=='calculator'
    assert plan['steps'][0]['arguments']['expression']=='2+3*4'

@pytest.mark.asyncio
async def test_local_core_does_not_fake_embeddings():
    provider=LocalCoreProvider()
    with pytest.raises(LLMError, match='AI_EMBEDDING_UNAVAILABLE'):
        await provider.embed(['alpha beta'])
