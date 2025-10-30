import os
import pytest
import requests
from typing import List

API_BASE = os.getenv("API_BASE")
TOKEN = os.getenv("TOKEN") 
TIMEOUT = 5

HEADERS = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}

# Devuelve la respuesta HTTP del endpoint /invoices con los parámetros y headers indicados.
def get_invoices(params: dict = None) -> requests.Response:
    url = f"{API_BASE.rstrip('/')}/invoices"
    return requests.get(url, params=params or {}, headers=HEADERS, timeout=TIMEOUT)

# Extrae y devuelve una lista de facturas desde la respuesta JSON, manejando distintos formatos comunes.
def safe_parse_json_array(resp: requests.Response) -> List:
    try:
        j = resp.json()
        if isinstance(j, list):
            return j
        if isinstance(j, dict):
            for k in ("data", "invoices", "items", "rows"):
                if k in j and isinstance(j[k], list):
                    return j[k]
        return []
    except ValueError:
        return []
    
# Verifica que la respuesta no contenga trazas, errores ni palabras clave propias de SQL.
def assert_no_sql_dump_or_trace(body_text: str):
    lower = body_text.lower()
    for bad in ("syntax error", "sql", "stacktrace", "exception", "fatal error", "select ", "insert ", "union "):
        assert bad not in lower, f"Respuesta contiene posible indicio de SQL/error: '{bad}'"

# Verifica que exista un token en el entorno; si no, salta los tests que requieren autenticación.
@pytest.fixture(scope="module")
def ensure_token_or_skip():
    if not TOKEN:
        pytest.skip("TOKEN no está en entorno. Exportá TOKEN para poder ejecutar tests autentificados.")
    return TOKEN

# Obtiene el listado de facturas limpio para establecer una referencia (baseline) de comparación.
def test_baseline_list_returns_array_or_empty(ensure_token_or_skip):
    resp = get_invoices()
    assert resp.status_code in (200, 204), f"Esperaba 200/204 para listado base, tuve {resp.status_code}: {resp.text}"
    invoices = safe_parse_json_array(resp)
    assert isinstance(invoices, list)
    pytest.baseline_count = len(invoices)

# Envía un payload de inyección SQL y comprueba que no amplíe resultados ni muestre errores SQL.
def test_sqli_in_query_params_do_not_expand_results(ensure_token_or_skip):
    baseline = getattr(pytest, "baseline_count", None)
    if baseline is None:
        pytest.skip("No se pudo determinar baseline_count; ejecutá test_baseline_list_returns_array_or_empty primero.")
    sqli_payload = "paid' OR '1'='1' -- "
    params = {"userId": "123", "operator": "=", "status": sqli_payload}
    resp = get_invoices(params=params)

    assert resp.status_code in (200, 400, 422, 403, 500), f"Status inesperado: {resp.status_code}"

    invoices = safe_parse_json_array(resp)
    if invoices:
        assert len(invoices) <= baseline, (
            "La respuesta con payload SQLi devuelve más filas que el baseline => posible SQLi exitosa."
        )

    assert_no_sql_dump_or_trace(resp.text)