from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


def _nmea_checksum(body: str) -> int:
    c = 0
    for ch in body:
        c ^= ord(ch) & 0xFF
    return c


def _nmea_deg_to_dm(value_deg: float, *, is_lat: bool) -> tuple[str, str]:
    # ddmm.mmmm (lat) / dddmm.mmmm (lon) + hemisphere
    hemi = "N" if is_lat else "E"
    if value_deg < 0:
        hemi = "S" if is_lat else "W"
    v = abs(float(value_deg))
    deg = int(v)
    minutes = (v - deg) * 60.0
    if is_lat:
        return f"{deg:02d}{minutes:07.4f}", hemi
    return f"{deg:03d}{minutes:07.4f}", hemi


def _build_rmc(*, dt: datetime, lat: float, lon: float, status: str = "A", speed_knots: float = 0.0, course_deg: float = 0.0) -> str:
    # $GPRMC,hhmmss.sss,A,llll.ll,a,yyyyy.yy,a,x.x,x.x,ddmmyy,,,A*CS
    t = dt.astimezone(timezone.utc)
    timestr = t.strftime("%H%M%S") + ".00"
    datestr = t.strftime("%d%m%y")
    lat_dm, lat_hemi = _nmea_deg_to_dm(lat, is_lat=True)
    lon_dm, lon_hemi = _nmea_deg_to_dm(lon, is_lat=False)
    spd = f"{float(speed_knots):.1f}"
    crs = f"{float(course_deg):.1f}"
    body = f"GPRMC,{timestr},{status},{lat_dm},{lat_hemi},{lon_dm},{lon_hemi},{spd},{crs},{datestr},,,"
    return body


class _NmeaProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._tick = 0

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        scenario = self._cfg.get("scenario") if isinstance(self._cfg.get("scenario"), dict) else None
        if scenario:
            now = datetime.now(timezone.utc)
            step_s = float(scenario.get("step_s", 1.0))
            dt = now + timedelta(seconds=(self._tick * step_s))
            stype = str(scenario.get("type", "static")).lower()
            if stype == "circle":
                lat0 = float(scenario.get("lat", 0.0))
                lon0 = float(scenario.get("lon", 0.0))
                radius_m = float(scenario.get("radius_m", 10.0))
                ang_deg = float(scenario.get("angular_speed_deg_per_step", 5.0)) * float(self._tick)
                ang = math.radians(ang_deg)
                dlat = (radius_m * math.cos(ang)) / 111_111.0
                dlon = (radius_m * math.sin(ang)) / (111_111.0 * max(0.1, math.cos(math.radians(lat0))))
                lat = lat0 + dlat
                lon = lon0 + dlon
                speed_knots = float(scenario.get("speed_knots", 0.0))
                course_deg = float(scenario.get("course_deg", ang_deg % 360.0))
            else:
                lat = float(scenario.get("lat", 0.0))
                lon = float(scenario.get("lon", 0.0))
                speed_knots = float(scenario.get("speed_knots", 0.0))
                course_deg = float(scenario.get("course_deg", 0.0))

            jitter_deg = float(scenario.get("jitter_deg", 0.0))
            if jitter_deg > 0 and mutated:
                j = int.from_bytes(mutated[:2].ljust(2, b"\x00"), "big") - 32768
                lat += j * jitter_deg / 32768.0
                k = int.from_bytes(mutated[2:4].ljust(2, b"\x00"), "big") - 32768
                lon += k * jitter_deg / 32768.0

            status = "A"
            drop = float(scenario.get("drop_fix_prob", 0.0))
            if drop > 0 and mutated:
                if (mutated[0] / 255.0) < drop:
                    status = "V"

            body = _build_rmc(dt=dt, lat=lat, lon=lon, status=status, speed_knots=speed_knots, course_deg=course_deg)
            self._tick += 1
        else:
            try:
                s = mutated.decode("ascii", errors="replace")
            except Exception:
                s = repr(mutated)

            s = s.strip("\r\n")
            if not s.startswith("$"):
                s = "$" + s.lstrip("$")

            # Split "$BODY*CS"
            if "*" in s:
                prefix, _cs = s.split("*", 1)
                body = prefix[1:]
            else:
                body = s[1:]

            # Bound body length to avoid runaway growth when using havoc.
            max_body = int(self._cfg.get("max_body_len", 120))
            body = body[:max_body]

        cs = _nmea_checksum(body)
        out = f"${body}*{cs:02X}\r\n".encode("ascii", errors="replace")
        return Message(data=out, meta={"nmea": {"body_len": len(body), "checksum": f"{cs:02X}"}})

    def parse(self, msg: Message) -> ParsedMessage:
        try:
            s = msg.data.decode("ascii", errors="replace").strip("\r\n")
        except Exception:
            s = repr(msg.data)
        fields: dict[str, Any] = {"len": len(msg.data)}
        if s.startswith("$"):
            body = s[1:]
            cs_text = None
            if "*" in body:
                body, cs_text = body.split("*", 1)
            fields["body"] = body
            fields["computed_checksum"] = f"{_nmea_checksum(body):02X}"
            if cs_text is not None:
                fields["checksum"] = cs_text[:2].upper()
                fields["checksum_matches"] = fields["checksum"] == fields["computed_checksum"]
            talker = body[:2] if len(body) >= 2 else None
            sentence = body[2:5] if len(body) >= 5 else None
            fields["talker"] = talker
            fields["sentence"] = sentence
        flow_key = None
        if fields.get("talker") and fields.get("sentence"):
            flow_key = f"nmea:{fields['talker']}:{fields['sentence']}"
        return ParsedMessage(protocol="nmea", level="app", ok=True, flow_key=flow_key, fields=fields, payload=ByteRange(0, len(msg.data)))


@register_protocol("gnss")
@register_protocol("nmea")
def nmea_protocol(config: dict[str, Any]) -> Protocol:
    return _NmeaProtocol(config)
