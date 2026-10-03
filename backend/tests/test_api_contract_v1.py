from pathlib import Path

ROOT=Path(__file__).parents[2]
MAIN=(ROOT/'backend/app/main.py').read_text()
CLIENT=(ROOT/'frontend/src/api.ts').read_text()
CONTRACTS=(ROOT/'frontend/src/contracts.ts').read_text()
IPC=(ROOT/'desktop/ipc/register.js').read_text()


def test_contract_version_is_frozen_across_backend_and_frontend():
    assert 'API_CONTRACT_VERSION = "1.0.0"' in MAIN
    assert "API_CONTRACT_VERSION = '1.0.0'" in CLIENT
    assert 'X-API-Contract-Version' in MAIN
    assert 'API_CONTRACT_MISMATCH' in CLIENT


def test_standard_failure_contract_is_shared():
    assert '"success":False,"error":{"code"' in MAIN
    assert '"request_id":request_id_var.get()' in MAIN
    assert "'error' in data" in CLIENT
    assert 'data?.error||data' in IPC


def test_frontend_types_do_not_use_any_escape_hatches():
    assert 'Record<string, unknown>' in CONTRACTS
    assert ' any' not in CONTRACTS


def test_ollama_ui_status_comes_from_backend_status_endpoint():
    assert '/api/v1/ollama/status' in IPC
    assert '/api/v1/ollama/test-chat' in IPC
    assert '/api/v1/ollama/test-embedding' in IPC
