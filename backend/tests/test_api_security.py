import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import app
from tests.conftest import TEST_TOKEN

client=TestClient(app)

def test_health_is_public():assert client.get('/api/v1/health').status_code==200

def test_protected_endpoint_requires_token():
    response=client.get('/api/v1/settings');assert response.status_code==401;assert 'token' not in response.text.lower()

def test_invalid_token_is_rejected():assert client.get('/api/v1/settings',headers={'Authorization':'Bearer wrong'}).status_code==401

def test_valid_token_is_allowed():assert client.get('/api/v1/settings',headers={'Authorization':f'Bearer {TEST_TOKEN}'}).status_code==200

def test_docs_are_protected():assert client.get('/docs').status_code==401

def test_production_cannot_start_without_token():
    with pytest.raises(ValidationError):Settings(_env_file=None,environment='production',auth_required=True,api_token=None)

def test_development_bypass_must_be_explicit():
    with pytest.raises(ValidationError):Settings(_env_file=None,environment='development',auth_required=False,allow_unauthenticated_localhost=False)

def test_memory_endpoints_reject_secrets_without_auditing():
    headers={'Authorization':f'Bearer {TEST_TOKEN}'}
    secret='api_key: sk-test-123456789012345678901234'
    with TestClient(app) as api:
        audit_before=api.get('/api/v1/audit',headers=headers).json()

        rejected=api.post('/api/v1/memories',headers=headers,json={'content':secret,'category':'note'})
        assert rejected.status_code==422
        assert api.get('/api/v1/audit',headers=headers).json()==audit_before

        created=api.post('/api/v1/memories',headers=headers,json={'content':'I prefer dark mode','category':'preference'})
        assert created.status_code==201
        memory=created.json()

        rejected_patch=api.patch(f'/api/v1/memories/{memory["id"]}',headers=headers,json={'content':'token=secret-token-value'})
        assert rejected_patch.status_code==422

        memories=api.get('/api/v1/memories',headers=headers).json()
        stored=next(item for item in memories if item['id']==memory['id'])
        assert stored['content']=='I prefer dark mode'

        memory_audits=[entry['event'] for entry in api.get('/api/v1/audit',headers=headers).json() if entry['details'].get('memory_id')==memory['id']]
        assert memory_audits==['memory.created']
