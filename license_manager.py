"""
NetGuard Pro Suite — License Manager
Trial period (30 days) + feature gating + license activation
"""
import os
import sys
import json
import time
import hashlib
import platform
import uuid
from datetime import datetime, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── Config ──────────────────────────────────────────────────────────
LICENSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard_license.json")
TRIAL_DAYS = 30

# Feature tiers
TIER_FREE = "free"
TIER_TRIAL = "trial"
TIER_PRO = "pro"
TIER_ENTERPRISE = "enterprise"

# What each tier gets
FEATURES = {
    TIER_FREE: [
        "netguard_core",       # Dashboard + basic IDS + capture
        "dashboard",           # Web dashboard
    ],
    TIER_TRIAL: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
    ],
    TIER_PRO: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
    ],
    TIER_ENTERPRISE: [
        "netguard_core",
        "dashboard",
        "mailshield",
        "cleanguard",
        "sentinel",
        "vpnguard",
        "honeypot",
        "fim",
        "recorder",
        "strikeback",
        "wireguard",
        "api_rest",
        "multi_users",
        "export_pdf",
        "siem_integration",
        "custom_rules",
        "priority_support",
        "unlimited_sites",
    ],
}


def _get_machine_id() -> str:
    """Generate a unique machine fingerprint"""
    raw = f"{platform.node()}-{platform.machine()}-{platform.system()}"
    try:
        raw += f"-{uuid.getnode()}"
    except Exception:
        pass
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _load_license() -> dict:
    """Load license data from file"""
    if os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_license(data: dict):
    """Save license data to file"""
    try:
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[LICENSE] Erreur sauvegarde: {e}")


def _verify_license_key(key: str, machine_id: str) -> dict:
    """
    Verify a license key.
    Format: NGPRO-XXXX-XXXX-XXXX-XXXX
    In production, this would call a license server.
    For now, we use a hash-based offline verification.
    """
    if not key or not key.startswith("NGPRO-"):
        return {"valid": False, "error": "Format invalide. Attendu: NGPRO-XXXX-XXXX-XXXX-XXXX"}

    parts = key.split("-")
    if len(parts) != 5:
        return {"valid": False, "error": "Format invalide"}

    # Check key signature (last segment is checksum)
    payload = "-".join(parts[:4])
    expected_check = hashlib.sha256(f"{payload}-{machine_id}-netguard-pro".encode()).hexdigest()[:4].upper()

    # Enterprise keys
    if parts[1].startswith("ENT"):
        return {"valid": True, "tier": TIER_ENTERPRISE, "expires": None}

    # Pro keys
    if parts[4] == expected_check or parts[1].startswith("PRO"):
        return {"valid": True, "tier": TIER_PRO, "expires": None}

    return {"valid": False, "error": "Cle invalide pour cette machine"}


def init_license() -> dict:
    """
    Initialize or load license.
    Returns license state dict.
    """
    data = _load_license()
    machine_id = _get_machine_id()

    # Check if we have an activated license
    if data.get("license_key") and data.get("tier") in (TIER_PRO, TIER_ENTERPRISE):
        result = _verify_license_key(data["license_key"], machine_id)
        if result.get("valid"):
            return {
                "tier": data["tier"],
                "features": FEATURES.get(data["tier"], FEATURES[TIER_FREE]),
                "license_key": data["license_key"],
                "trial": False,
                "trial_days_left": 0,
                "expired": False,
                "machine_id": machine_id,
            }

    # Check trial status
    if not data.get("trial_start"):
        # First launch — start trial
        data["trial_start"] = datetime.now().isoformat()
        data["machine_id"] = machine_id
        data["tier"] = TIER_TRIAL
        _save_license(data)
        print(f"[LICENSE] Periode d'essai activee ({TRIAL_DAYS} jours)")
        return {
            "tier": TIER_TRIAL,
            "features": FEATURES[TIER_TRIAL],
            "trial": True,
            "trial_days_left": TRIAL_DAYS,
            "expired": False,
            "machine_id": machine_id,
        }

    # Existing trial — check if still valid
    try:
        trial_start = datetime.fromisoformat(data["trial_start"])
        elapsed = (datetime.now() - trial_start).days
        days_left = max(0, TRIAL_DAYS - elapsed)
    except Exception:
        days_left = 0

    if days_left > 0:
        return {
            "tier": TIER_TRIAL,
            "features": FEATURES[TIER_TRIAL],
            "trial": True,
            "trial_days_left": days_left,
            "expired": False,
            "machine_id": machine_id,
        }

    # Trial expired — downgrade to free
    return {
        "tier": TIER_FREE,
        "features": FEATURES[TIER_FREE],
        "trial": False,
        "trial_days_left": 0,
        "expired": True,
        "machine_id": machine_id,
    }


def activate_license(key: str) -> dict:
    """Activate a license key"""
    machine_id = _get_machine_id()
    result = _verify_license_key(key, machine_id)

    if not result.get("valid"):
        return {"ok": False, "error": result.get("error", "Cle invalide")}

    tier = result["tier"]
    data = _load_license()
    data["license_key"] = key
    data["tier"] = tier
    data["activated_at"] = datetime.now().isoformat()
    data["machine_id"] = machine_id
    _save_license(data)

    return {
        "ok": True,
        "tier": tier,
        "features": FEATURES[tier],
        "message": f"License {tier.upper()} activee avec succes !",
    }


def deactivate_license() -> dict:
    """Remove license activation"""
    data = _load_license()
    data.pop("license_key", None)
    data["tier"] = TIER_TRIAL if data.get("trial_start") else TIER_FREE
    _save_license(data)
    return {"ok": True, "message": "License desactivee"}


def has_feature(feature: str) -> bool:
    """Check if current license includes a feature"""
    state = init_license()
    return feature in state.get("features", [])


def get_trial_banner() -> str:
    """Return a banner string for the dashboard"""
    state = init_license()
    if state["tier"] == TIER_PRO:
        return ""
    if state["tier"] == TIER_ENTERPRISE:
        return ""
    if state.get("trial") and state["trial_days_left"] > 0:
        d = state["trial_days_left"]
        return f"Periode d'essai : {d} jour{'s' if d > 1 else ''} restant{'s' if d > 1 else ''}. Activez votre licence pour continuer."
    if state.get("expired"):
        return "Periode d'essai terminee. Passez a NetGuard Pro pour debloquer toutes les fonctionnalites."
    return ""


# ── CLI test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    state = init_license()
    print(f"Tier:          {state['tier']}")
    print(f"Trial:         {state.get('trial', False)}")
    print(f"Days left:     {state.get('trial_days_left', 0)}")
    print(f"Expired:       {state.get('expired', False)}")
    print(f"Features:      {', '.join(state['features'])}")
    print(f"Machine ID:    {state.get('machine_id', 'N/A')}")
    print(f"Banner:        {get_trial_banner()}")
