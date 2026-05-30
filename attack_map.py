# ============================================
# ThreatWatch AI - Live Attack Map
# ============================================
# Generates a world map showing:
#   - Where attacks are coming from
#   - Attack type and risk level
#   - Animated pulsing dots
#   - Color coded by severity
# ============================================

import folium
import json
import os
import random
import datetime

LOG_FILE   = "logs/threats.json"
MAP_OUTPUT = "reports/attack_map.html"

# -----------------------------------------------
# FAKE GEO DATA FOR SIMULATED IPs
# Maps IP ranges to countries/cities
# -----------------------------------------------
IP_LOCATIONS = {
    "192.168.221.128": {"country": "Pakistan",       "city": "Islamabad",   "lat": 33.6844, "lon": 73.0479,  "flag": "🇵🇰"},
    "192.168.1.105":   {"country": "Russia",         "city": "Moscow",      "lat": 55.7558, "lon": 37.6173,  "flag": "🇷🇺"},
    "172.16.8.22":     {"country": "China",          "city": "Beijing",     "lat": 39.9042, "lon": 116.4074, "flag": "🇨🇳"},
    "10.0.0.44":       {"country": "United States",  "city": "New York",    "lat": 40.7128, "lon": -74.0060, "flag": "🇺🇸"},
    "192.168.1.200":   {"country": "North Korea",    "city": "Pyongyang",   "lat": 39.0194, "lon": 125.7381, "flag": "🇰🇵"},
    "10.0.0.99":       {"country": "Iran",           "city": "Tehran",      "lat": 35.6892, "lon": 51.3890,  "flag": "🇮🇷"},
    "192.168.1.77":    {"country": "Brazil",         "city": "Sao Paulo",   "lat": -23.5505,"lon": -46.6333, "flag": "🇧🇷"},
    "159.31.24.96":    {"country": "Germany",        "city": "Berlin",      "lat": 52.5200, "lon": 13.4050,  "flag": "🇩🇪"},
    "159.52.240.231":  {"country": "Netherlands",    "city": "Amsterdam",   "lat": 52.3676, "lon": 4.9041,   "flag": "🇳🇱"},
    "242.93.97.12":    {"country": "Ukraine",        "city": "Kyiv",        "lat": 50.4501, "lon": 30.5234,  "flag": "🇺🇦"},
}

# Target location (STMU, Islamabad)
TARGET = {"lat": 33.6844, "lon": 73.0479, "name": "ThreatWatch AI — STMU"}

# Colors by severity
SEVERITY_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH":     "#ff6600",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#00ff88",
}

def get_severity(score):
    if score >= 90: return "CRITICAL"
    elif score >= 70: return "HIGH"
    elif score >= 40: return "MEDIUM"
    else: return "LOW"

def get_location(ip):
    """Get location for an IP address."""
    if ip in IP_LOCATIONS:
        return IP_LOCATIONS[ip]
    # Generate random location for unknown IPs
    random.seed(hash(ip))
    locations = [
        {"country": "Russia",        "city": "Moscow",      "lat": 55.7558,  "lon": 37.6173,  "flag": "🇷🇺"},
        {"country": "China",         "city": "Shanghai",    "lat": 31.2304,  "lon": 121.4737, "flag": "🇨🇳"},
        {"country": "United States", "city": "Los Angeles", "lat": 34.0522,  "lon": -118.2437,"flag": "🇺🇸"},
        {"country": "Brazil",        "city": "Rio",         "lat": -22.9068, "lon": -43.1729, "flag": "🇧🇷"},
        {"country": "India",         "city": "Mumbai",      "lat": 19.0760,  "lon": 72.8777,  "flag": "🇮🇳"},
        {"country": "UK",            "city": "London",      "lat": 51.5074,  "lon": -0.1278,  "flag": "🇬🇧"},
        {"country": "Germany",       "city": "Frankfurt",   "lat": 50.1109,  "lon": 8.6821,   "flag": "🇩🇪"},
        {"country": "Japan",         "city": "Tokyo",       "lat": 35.6762,  "lon": 139.6503, "flag": "🇯🇵"},
        {"country": "Australia",     "city": "Sydney",      "lat": -33.8688, "lon": 151.2093, "flag": "🇦🇺"},
        {"country": "Iran",          "city": "Tehran",      "lat": 35.6892,  "lon": 51.3890,  "flag": "🇮🇷"},
    ]
    return random.choice(locations)


def generate_attack_map():
    """Generate the full interactive attack map."""

    # Load threats
    if not os.path.exists(LOG_FILE):
        print("No threat data found. Run main.py first!")
        return

    with open(LOG_FILE, "r") as f:
        threats = json.load(f)

    print(f"Generating attack map for {len(threats)} threats...")

    # -----------------------------------------------
    # CREATE MAP
    # Dark theme world map centered on target
    # -----------------------------------------------
    m = folium.Map(
        location    = [20, 0],
        zoom_start  = 2,
        tiles       = "CartoDB dark_matter",
        prefer_canvas=True
    )

    # -----------------------------------------------
    # ADD TARGET MARKER (Your system)
    # -----------------------------------------------
    folium.Marker(
        location = [TARGET["lat"], TARGET["lon"]],
        popup    = folium.Popup(f"""
            <div style='font-family:monospace;background:#0d1b2a;color:#00ff88;padding:10px;border-radius:6px;min-width:200px'>
                <b style='color:#00ff88'>🛡 {TARGET['name']}</b><br>
                <span style='color:#aaa'>Protected System</span><br>
                <span style='color:#00aaff'>Islamabad, Pakistan</span>
            </div>
        """, max_width=250),
        icon = folium.Icon(color="green", icon="shield", prefix="fa")
    ).add_to(m)

    # -----------------------------------------------
    # ADD ATTACK MARKERS & LINES
    # -----------------------------------------------
    seen_ips = {}

    for threat in threats:
        ip       = threat["ip_address"]
        score    = threat["risk_score"]
        severity = get_severity(score)
        color    = SEVERITY_COLORS[severity]
        loc      = get_location(ip)

        # Count attacks per IP
        if ip not in seen_ips:
            seen_ips[ip] = {"count": 0, "loc": loc, "threats": [], "max_score": 0}
        seen_ips[ip]["count"]    += 1
        seen_ips[ip]["max_score"] = max(seen_ips[ip]["max_score"], score)
        seen_ips[ip]["threats"].append(threat["threat_type"])

    # Add markers and attack lines
    for ip, data in seen_ips.items():
        loc      = data["loc"]
        count    = data["count"]
        score    = data["max_score"]
        severity = get_severity(score)
        color    = SEVERITY_COLORS[severity]
        threats_list = list(set(data["threats"]))[:3]

        # Size based on attack count
        radius = min(8 + count * 2, 25)

        # Pulsing circle marker
        folium.CircleMarker(
            location      = [loc["lat"], loc["lon"]],
            radius        = radius,
            color         = color,
            fill          = True,
            fill_color    = color,
            fill_opacity  = 0.7,
            weight        = 2,
            popup         = folium.Popup(f"""
                <div style='font-family:monospace;background:#0d1b2a;color:#e0e0e0;padding:12px;border-radius:6px;min-width:220px;border:1px solid {color}'>
                    <b style='color:{color}'>{loc['flag']} {loc['city']}, {loc['country']}</b><br><br>
                    <span style='color:#aaa'>Attacker IP:</span> <span style='color:#00aaff'>{ip}</span><br>
                    <span style='color:#aaa'>Attacks:</span> <span style='color:{color}'>{count}</span><br>
                    <span style='color:#aaa'>Max Score:</span> <span style='color:{color}'>{score}/100</span><br>
                    <span style='color:#aaa'>Severity:</span> <span style='color:{color}'>{severity}</span><br>
                    <span style='color:#aaa'>Types:</span> {', '.join(threats_list)}
                </div>
            """, max_width=280),
            tooltip = f"{loc['flag']} {loc['country']} — {severity} ({count} attacks)"
        ).add_to(m)

        # Draw attack line to target
        folium.PolyLine(
            locations   = [[loc["lat"], loc["lon"]], [TARGET["lat"], TARGET["lon"]]],
            color       = color,
            weight      = 1.5,
            opacity     = 0.5,
            dash_array  = "5 5"
        ).add_to(m)

    # -----------------------------------------------
    # ADD LEGEND & STATS
    # -----------------------------------------------
    total    = len(threats)
    critical = sum(1 for t in threats if t["risk_score"] >= 90)
    high     = sum(1 for t in threats if 70 <= t["risk_score"] < 90)
    blocked  = sum(1 for t in threats if t["action_taken"] == "IP Blocked")

    legend_html = f"""
    <div style="
        position: fixed; bottom: 30px; left: 30px; z-index: 1000;
        background: rgba(13,27,42,0.95); border: 1px solid #1a3a5c;
        border-radius: 10px; padding: 16px; font-family: 'Courier New', monospace;
        min-width: 220px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    ">
        <div style="color:#00ff88;font-size:14px;font-weight:bold;margin-bottom:12px;letter-spacing:2px">
            🛡 THREATWATCH AI
        </div>
        <div style="color:#aaa;font-size:11px;margin-bottom:10px">LIVE ATTACK MAP</div>
        <div style="margin-bottom:8px">
            <span style="color:#ff0000">●</span> <span style="color:#e0e0e0;font-size:11px">CRITICAL (90-100)</span>
        </div>
        <div style="margin-bottom:8px">
            <span style="color:#ff6600">●</span> <span style="color:#e0e0e0;font-size:11px">HIGH (70-89)</span>
        </div>
        <div style="margin-bottom:8px">
            <span style="color:#ffcc00">●</span> <span style="color:#e0e0e0;font-size:11px">MEDIUM (40-69)</span>
        </div>
        <div style="margin-bottom:14px">
            <span style="color:#00ff88">●</span> <span style="color:#e0e0e0;font-size:11px">LOW (0-39)</span>
        </div>
        <div style="border-top:1px solid #1a3a5c;padding-top:10px">
            <div style="color:#00aaff;font-size:12px">Total Attacks: <b style="color:#fff">{total}</b></div>
            <div style="color:#ff0000;font-size:12px">Critical: <b style="color:#fff">{critical}</b></div>
            <div style="color:#ff6600;font-size:12px">High: <b style="color:#fff">{high}</b></div>
            <div style="color:#ff4444;font-size:12px">IPs Blocked: <b style="color:#fff">{blocked}</b></div>
            <div style="color:#666;font-size:10px;margin-top:8px">
                Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
            </div>
        </div>
    </div>
    """

    title_html = """
    <div style="
        position: fixed; top: 20px; left: 50%; transform: translateX(-50%);
        z-index: 1000; background: rgba(13,27,42,0.95);
        border: 1px solid #00ff88; border-radius: 8px;
        padding: 10px 24px; font-family: 'Courier New', monospace;
        text-align: center;
    ">
        <span style="color:#00ff88;font-size:15px;letter-spacing:3px;font-weight:bold">
            🛡 THREATWATCH AI — LIVE GLOBAL ATTACK MAP
        </span>
        <div style="color:#666;font-size:10px;margin-top:4px">
            Click any dot for attack details • Lines show attack origin → target
        </div>
    </div>
    """

    m.get_root().html.add_child(folium.Element(legend_html))
    m.get_root().html.add_child(folium.Element(title_html))

    # Save map
    os.makedirs("reports", exist_ok=True)
    m.save(MAP_OUTPUT)

    print(f"\n✅ Attack map saved to: {MAP_OUTPUT}")
    print(f"   Total attacks mapped: {total}")
    print(f"   Unique attacker IPs:  {len(seen_ips)}")
    print(f"\n   Open this file in your browser:")
    print(f"   {os.path.abspath(MAP_OUTPUT)}")

    return MAP_OUTPUT


if __name__ == "__main__":
    print("="*50)
    print("  ThreatWatch AI — Attack Map Generator")
    print("="*50 + "\n")
    generate_attack_map()