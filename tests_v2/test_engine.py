"""Bridge templates must not rewrite existing Xray rules or leak real UUIDs."""
import copy
import json
import uuid
import pytest
from v2.template_engine import (
    Endpoint, Exit, TemplateError, diff_configs, extend_existing_bridge,
    render_bridge, safe_preview, validate_rendered, variables_map,
)

def source():
    return Endpoint("RUS1","rus1.gowayot.com","RU")

def dest(code="DE1", domain="de1.gowayot.com", port=None):
    return Exit(Endpoint(code,domain,code[:2]),str(uuid.uuid4()),inbound_port=port)

def test_first_exit_matches_existing_filter_semantics():
    e=dest()
    config=render_bridge(source(),[e])
    assert [i["port"] for i in config["inbounds"]]==[443,8443]
    assert config["inbounds"][0]["tag"]=="RUS1_DE1_VLESS_TLS_IN"
    assert config["inbounds"][1]["tag"]=="RUS1_FILTER_VLESS_TLS_IN"
    assert config["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"] == "/opt/nginx/certs/rus1.gowayot.com_privkey.key"
    assert config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]==e.user_id
    assert [r.get("outboundTag") for r in config["routing"]["rules"]][:3]==["BLOCKED"]*3
    assert config["routing"]["rules"][3]["domain"]==["geosite:youtube"]
    assert config["routing"]["rules"][4]["ip"]==["geoip:ru"]
    assert config["routing"]["rules"][5]["domain"]==["geosite:category-ru"]
    assert config["routing"]["domainStrategy"]=="IPIfNonMatch"
    validate_rendered(config)

def test_second_exit_is_dedicated_route_not_accidental_default():
    de,nl=dest(),dest("NL1","nl1.gowayot.com")
    config=render_bridge(source(),[de,nl])
    assert [i["port"] for i in config["inbounds"]]==[443,8443,8444]
    assert config["inbounds"][-1]["tag"]=="RUS1_NL1_VLESS_TLS_IN"
    assert config["routing"]["rules"][-1]["inboundTag"]==["RUS1_NL1_VLESS_TLS_IN"]
    assert config["routing"]["rules"][-1]["outboundTag"]=="TO_NL1_VLESS_TLS_OUT"
    assert config["routing"]["rules"][7]["outboundTag"]=="TO_DE1_VLESS_TLS_OUT"
    assert config["outbounds"][1]["tag"]=="TO_NL1_VLESS_TLS_OUT"

def test_append_to_working_json_preserves_every_existing_field():
    de,nl=dest(),dest("NL1","nl1.gowayot.com")
    current=render_bridge(source(),[de])
    current["log"]["loglevel"]="error"
    current["inbounds"][0]["settings"]["sniffOverride"]=True
    current["routing"]["rules"][3]["domain"]=["geosite:youtube","example.com"]
    prior=copy.deepcopy(current)
    result=extend_existing_bridge(current,source(),nl)
    assert current==prior
    assert result["inbounds"][:2]==current["inbounds"]
    assert result["outbounds"][:3]==current["outbounds"]
    assert result["routing"]["rules"][:8]==current["routing"]["rules"]
    assert result["log"]==current["log"]
    assert result["inbounds"][-1]["port"]==8444
    assert result["outbounds"][-1]["tag"]=="TO_NL1_VLESS_TLS_OUT"
    assert result["routing"]["rules"][-1]["outboundTag"]=="TO_NL1_VLESS_TLS_OUT"

def test_append_handles_used_port_without_rewriting_existing_route():
    de=dest()
    current=render_bridge(source(),[de])
    current["inbounds"].append(copy.deepcopy(current["inbounds"][0]))
    current["inbounds"][-1].update({"tag":"ADDITIONAL","port":8444})
    added=extend_existing_bridge(current,source(),dest("NL1","nl1.gowayot.com"))
    assert added["inbounds"][-1]["port"]==8445

def test_collisions_and_bad_naming_are_rejected():
    with pytest.raises(TemplateError):
        Endpoint("rus1","rus1.example.com","RU")
    with pytest.raises(TemplateError):
        Endpoint("RU1","127.0.0.1","RU")
    with pytest.raises(TemplateError):
        render_bridge(source(),[dest(),dest("DE1","other.gowayot.com")])
    current=render_bridge(source(),[dest()])
    with pytest.raises(TemplateError):
        extend_existing_bridge(current,source(),dest("NL1","nl1.gowayot.com",8443))
    with pytest.raises(TemplateError):
        extend_existing_bridge(current,source(),dest("DE1","de1.gowayot.com"))

def test_invalid_tags_rejected():
    config=render_bridge(source(),[dest()])
    config["routing"]["rules"][-1]["outboundTag"]="DOES_NOT_EXIST"
    with pytest.raises(TemplateError):
        validate_rendered(config)

def test_previews_hide_credentials_and_show_real_change():
    de,nl=dest(),dest("NL1","nl1.gowayot.com")
    original=render_bridge(source(),[de])
    proposed=extend_existing_bridge(original,source(),nl)
    diff=diff_configs(safe_preview(original),safe_preview(proposed))
    serialized=json.dumps(safe_preview(proposed))
    assert de.user_id not in serialized
    assert nl.user_id not in serialized
    assert de.user_id not in diff
    assert nl.user_id not in diff
    assert "TO_NL1_VLESS_TLS_OUT" in diff
    assert "{{" not in json.dumps(proposed)
    values=variables_map(source(),[nl])
    assert any(x["key"]=="source.domain" for x in values)
    assert all(nl.user_id not in x["preview"] for x in values)
