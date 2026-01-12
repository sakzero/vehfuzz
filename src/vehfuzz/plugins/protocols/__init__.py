from __future__ import annotations

# Import built-in protocols to register them.
from vehfuzz.plugins.protocols.can import can_protocol  # noqa: F401
from vehfuzz.plugins.protocols.can_dbc import can_dbc_protocol  # noqa: F401
from vehfuzz.plugins.protocols.doip import doip_protocol  # noqa: F401
from vehfuzz.plugins.protocols.j1939 import j1939_protocol  # noqa: F401
from vehfuzz.plugins.protocols.nmea import nmea_protocol  # noqa: F401
from vehfuzz.plugins.protocols.raw import raw_protocol  # noqa: F401
from vehfuzz.plugins.protocols.someip import someip_protocol  # noqa: F401
from vehfuzz.plugins.protocols.someip_sd import someip_sd_protocol  # noqa: F401
from vehfuzz.plugins.protocols.uds import uds_protocol  # noqa: F401
from vehfuzz.plugins.protocols.wifi import wifi_protocol  # noqa: F401
from vehfuzz.plugins.protocols.bluetooth import bluetooth_protocol  # noqa: F401
