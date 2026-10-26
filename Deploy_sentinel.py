#!/usr/bin/env python3

import argparse
import os
import re
import sys
import time
import uuid
from pathlib import Path

import requests
import yaml
from azure.identity import DefaultAzureCredential

API_VERSION = "2025-06-01"
ARM = "https://management.azure.com"
SCOPE = "https://management.azure.com/.default"

OPERATORS = {
    "gt": "GreaterThan",
    "lt": "LessThan",
    "eq": "Equal",
    "ne": "NotEqual",
}
SEVERITIES = {"informational", "low", "medium", "high"}


def to_iso_duration(value: str) -> str:
    """Converte '5m', '1h', '1d' para ISO 8601 (PT5M, PT1H, P1D)."""
    value = str(value).strip()
    if value.upper().startswith("P"):
        return value.upper()
    m = re.fullmatch(r"(\d+)([mhd])", value.lower())
    if not m:
        raise ValueError(f"Duração inválida: '{value}' (use 5m, 1h, 1d ou ISO 8601)")
    n, unit = m.groups()
    return {"m": f"PT{n}M", "h": f"PT{n}H", "d": f"P{n}D"}[unit]


GROUPING_METHODS = {
    "allentities": "AllEntities",
    "anyalert": "AnyAlert",
    "selected": "Selected",
}


def build_incident_configuration(cfg: dict) -> dict:
    """Converte incidentConfiguration do YAML para o formato da API.

    createIncident: true/false  -> cria (ou não) incidente a partir dos alertas
    groupingConfiguration       -> como os alertas são agrupados em incidentes
    """
    result = {"createIncident": bool(cfg.get("createIncident", True))}

    grouping = cfg.get("groupingConfiguration")
    if grouping:
        method_raw = str(grouping.get("matchingMethod", "AllEntities"))
        method = GROUPING_METHODS.get(method_raw.lower())
        if not method:
            raise ValueError(
                f"matchingMethod inválido: '{method_raw}' "
                f"(use AllEntities, AnyAlert ou Selected)"
            )

        group_by = {
            k: grouping[k]
            for k in ("groupByEntities", "groupByAlertDetails", "groupByCustomDetails")
            if grouping.get(k)
        }
###        if group_by and method != "Selected":
##            raise ValueError(
#                "groupByEntities/groupByAlertDetails/groupByCustomDetails "
#                "só valem com matchingMethod: Selected"
#            )

        result["groupingConfiguration"] = {
            "enabled": bool(grouping.get("enabled", False)),
            "reopenClosedIncident": bool(grouping.get("reopenClosedIncident", False)),
            "lookbackDuration": to_iso_duration(grouping.get("lookbackDuration", "5h")),
            "matchingMethod": method,
            **group_by,
        }

    return result


def build_payload(rule: dict) -> dict:
    """Converte o YAML da regra para o body da API."""
    required = ["name", "severity", "query", "queryFrequency", "queryPeriod"]
    missing = [k for k in required if k not in rule]
    if missing:
        raise ValueError(f"Campos obrigatórios ausentes: {', '.join(missing)}")

    severity = str(rule["severity"]).lower()
    if severity not in SEVERITIES:
        raise ValueError(f"Severity inválida: {rule['severity']}")

    techniques, subTechniques = [], []
    for t in rule.get("relevantTechniques", []) or []:
        (subTechniques if "." in t else techniques).append(t)
        # garante que a técnica pai também esteja listada
        if "." in t and t.split(".")[0] not in techniques:
            techniques.append(t.split(".")[0])

    props = {
        "displayName": rule["name"],
        "description": (rule.get("description") or "").strip(),
        "severity": severity.capitalize(),
        "enabled": rule.get("enabled", True),
        "query": rule["query"],
        "queryFrequency": to_iso_duration(rule["queryFrequency"]),
        "queryPeriod": to_iso_duration(rule["queryPeriod"]),
        "triggerOperator": OPERATORS[str(rule.get("triggerOperator", "gt")).lower()],
        "triggerThreshold": int(rule.get("triggerThreshold", 0)),
        "suppressionEnabled": False,
        "suppressionDuration": "PT1H",  # obrigatório na API mesmo desabilitado
        "tactics": rule.get("tactics", []) or [],
        "techniques": techniques,
        "subTechniques": sub_techniques,
    }

    # Campos opcionais repassados quase como estão
    if rule.get("entityMappings"):
        props["entityMappings"] = rule["entityMappings"]
    if rule.get("customDetails"):
        props["customDetails"] = rule["customDetails"]
    if rule.get("alertDetailsOverride"):
        props["alertDetailsOverride"] = rule["alertDetailsOverride"]
    if rule.get("eventGroupingSettings"):
        props["eventGroupingSettings"] = rule["eventGroupingSettings"]
    if rule.get("incidentConfiguration"):
        props["incidentConfiguration"] = build_incident_configuration(
            rule["incidentConfiguration"]
        )

    return {"kind": "Scheduled", "properties": props}


def rule_id(rule: dict) -> str:
    """Usa o id do YAML; se não existir, gera um UUID5 estável a partir do nome."""
    if rule.get("id"):
        return str(uuid.UUID(str(rule["id"])))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel-rule:{rule['name']}"))


def put_rule(session: requests.Session, base_url: str, rid: str, payload: dict) -> requests.Response:
    url = f"{base_url}/{rid}?api-version={API_VERSION}"
    for attempt in range(5):
        resp = session.put(url, json=payload, timeout=60)
        if resp.status_code in (429, 500, 502, 503, 504):
            wait = int(resp.headers.get("Retry-After", 2 ** attempt))
            print(f"    ↻ HTTP {resp.status_code}, tentando de novo em {wait}s...")
            time.sleep(wait)
            continue
        return resp
    return resp


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy de regras YAML no Microsoft Sentinel")
    parser.add_argument("--rules-dir", required=True, help="Diretório com os .yaml/.yml")
    parser.add_argument("--dry-run", action="store_true", help="Valida e mostra o payload sem enviar")
    args = parser.parse_args()

    sub = os.environ.get("SENTINEL_SUBSCRIPTION_ID")
    rg = os.environ.get("SENTINEL_RESOURCE_GROUP")
    ws = os.environ.get("SENTINEL_WORKSPACE_NAME")
    if not args.dry_run and not all([sub, rg, ws]):
        print("Defina SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP e SENTINEL_WORKSPACE_NAME.")
        return 2

    base_url = (
        f"{ARM}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )

    session = requests.Session()
    if not args.dry_run:
        token = DefaultAzureCredential().get_token(SCOPE).token
        session.headers.update(
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        )

    files = sorted(
        list(Path(args.rules_dir).rglob("*.yaml")) + list(Path(args.rules_dir).rglob("*.yml"))
    )
    if not files:
        print(f"Nenhuma regra encontrada em {args.rules_dir}")
        return 1

    ok, failed = 0, []
    for f in files:
        try:
            rule = yaml.safe_load(f.read_text(encoding="utf-8"))
            rid = rule_id(rule)
            payload = build_payload(rule)
        except Exception as e:  # erro de validação/parse
            print(f"✗ {f}: {e}")
            failed.append(str(f))
            continue

        if args.dry_run:
            print(f"✓ [dry-run] {f} → {rule['name']} ({rid})")
            continue

        resp = put_rule(session, base_url, rid, payload)
        if resp.status_code in (200, 201):
            action = "criada" if resp.status_code == 201 else "atualizada"
            print(f"✓ {rule['name']} {action} ({rid})")
            ok += 1
        else:
            print(f"✗ {rule['name']}: HTTP {resp.status_code} - {resp.text[:500]}")
            failed.append(str(f))

    print(f"\nResumo: {ok} enviadas, {len(failed)} com falha, {len(files)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())