"""OpenAPI inventory parsing: endpoints, params, schemas, auth requirements."""

EXPECTED = {
    ("GET", "/api/items"), ("POST", "/api/items"), ("GET", "/api/items/{id}"),
    ("GET", "/api/admin/stats"), ("GET", "/api/users/{id}/profile"), ("POST", "/api/login"),
}


def test_every_lab_route_is_inventoried(spec):
    assert {(e["method"], e["path"]) for e in spec["endpoints"]} == EXPECTED


def test_auth_requirements_per_operation(spec):
    auth = {(e["method"], e["path"]): e["auth"] for e in spec["endpoints"]}
    assert auth[("GET", "/api/admin/stats")] is True
    assert auth[("GET", "/api/users/{id}/profile")] is True
    assert auth[("GET", "/api/items")] is False
    assert auth[("POST", "/api/login")] is False


def test_path_params_are_extracted(spec):
    params = {e["path"]: e["params"] for e in spec["endpoints"]}
    assert params["/api/items/{id}"] == ["id"]
    assert params["/api/users/{id}/profile"] == ["id"]
    assert params["/api/items"] == []


def test_schemas_resolve_and_describe_objects(spec):
    schemas = spec["schemas"]
    for ep in spec["endpoints"]:
        assert ep["response_schema"] in schemas, ep
    assert "owner_id" in schemas["Item"]
    assert "description" in schemas["Item"]
    # the summary schema must not advertise credential columns
    assert not any("password" in f for f in schemas["ItemSummary"])
