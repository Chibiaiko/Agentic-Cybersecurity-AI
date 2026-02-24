# 🦅 nest/tenable_enrichment.py
# ---------------------------------------------------------
# SentinelHawk — Tenable.io Vulnerability Enrichment
# ---------------------------------------------------------

import requests

class TenableEnrichment:

    def __init__(self, access_key, secret_key):
        self.base_url = "https://cloud.tenable.com"
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"
        }

    def get_asset_vulnerabilities(self, hostname):
        """
        Fetch Tenable asset vulnerabilities and return a risk modifier.
        """
        if not hostname:
            return {"critical": 0, "high": 0, "risk_modifier": 0}

        try:
            url = f"{self.base_url}/workbenches/assets"
            params = {
                "filter.0.filter": "hostname",
                "filter.0.quality": "eq",
                "filter.0.value": hostname
            }

            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=5
            )

            if response.status_code != 200:
                # Silent fail for demo/simulation
                return {"critical": 0, "high": 0, "risk_modifier": 0}

            data = response.json()
            assets = data.get("assets", [])
            if not assets:
                return {"critical": 0, "high": 0, "risk_modifier": 0}

            asset = assets[0]
            critical = asset.get("critical", 0)
            high = asset.get("high", 0)
            risk_modifier = (critical * 10) + (high * 5)

            return {
                "critical": critical,
                "high": high,
                "risk_modifier": risk_modifier
            }

        except Exception:
            return {"critical": 0, "high": 0, "risk_modifier": 0}
