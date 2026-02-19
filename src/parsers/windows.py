"""
Windows Event Log Parser
XML formatında export edilmiş Windows Event Log dosyalarını destekler.
Ayrıca EVTX formatı için python-evtx kullanımı gösterilmiştir.
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, Iterator
from dataclasses import dataclass, field


@dataclass
class WindowsEventEntry:
    """Parse edilmiş Windows Event Log kaydı."""
    event_id: int
    timestamp: datetime
    level: str
    channel: str
    computer: str
    user: str
    message: str
    source: str
    raw: str
    event_data: dict = field(default_factory=dict)
    system_data: dict = field(default_factory=dict)


LEVEL_MAP = {
    "0": "LOGALWAYS",
    "1": "CRITICAL",
    "2": "ERROR",
    "3": "WARNING",
    "4": "INFORMATION",
    "5": "VERBOSE",
}

# Windows XML Event namespace
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class WindowsEventParser:
    """Windows Event Log XML dosyalarını parse eden sınıf."""

    def parse_xml_file(self, filepath: str) -> Iterator[WindowsEventEntry]:
        """
        XML formatında export edilmiş event log dosyasını parse eder.

        Args:
            filepath: XML dosyası yolu

        Yields:
            WindowsEventEntry nesneleri
        """
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError:
            return

        # Kök eleman <Events> ise alt elementleri işle
        if root.tag.endswith("Events"):
            events = root
        else:
            events = [root]

        for event_elem in events:
            entry = self._parse_event_element(event_elem)
            if entry:
                yield entry

    def parse_xml_string(self, xml_string: str) -> Optional[WindowsEventEntry]:
        """
        Tek bir XML event stringini parse eder.

        Args:
            xml_string: XML string

        Returns:
            WindowsEventEntry veya None
        """
        try:
            root = ET.fromstring(xml_string)
            return self._parse_event_element(root)
        except ET.ParseError:
            return None

    def _parse_event_element(self, elem: ET.Element) -> Optional[WindowsEventEntry]:
        """XML elementini WindowsEventEntry'e çevirir."""
        try:
            # Namespace'i normalize et
            tag = elem.tag
            ns_match = re.match(r'\{([^}]+)\}', tag)
            ns = f"{{{ns_match.group(1)}}}" if ns_match else ""

            system = elem.find(f"{ns}System")
            if system is None:
                return None

            # Event ID
            event_id_elem = system.find(f"{ns}EventID")
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0

            # Zaman
            time_created = system.find(f"{ns}TimeCreated")
            timestamp_str = time_created.get("SystemTime", "") if time_created is not None else ""
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now()

            # Seviye
            level_elem = system.find(f"{ns}Level")
            level_val = level_elem.text if level_elem is not None else "4"
            level = LEVEL_MAP.get(str(level_val), "INFORMATION")

            # Kanal
            channel_elem = system.find(f"{ns}Channel")
            channel = channel_elem.text if channel_elem is not None else "Unknown"

            # Bilgisayar
            computer_elem = system.find(f"{ns}Computer")
            computer = computer_elem.text if computer_elem is not None else "Unknown"

            # Kaynak (Provider)
            provider = system.find(f"{ns}Provider")
            source = provider.get("Name", "Unknown") if provider is not None else "Unknown"

            # Kullanıcı
            security = system.find(f"{ns}Security")
            user = security.get("UserID", "N/A") if security is not None else "N/A"

            # Event Data
            event_data_elem = elem.find(f"{ns}EventData")
            event_data = {}
            if event_data_elem is not None:
                for data in event_data_elem.findall(f"{ns}Data"):
                    name = data.get("Name", "Data")
                    event_data[name] = data.text or ""

            # Mesaj oluştur
            message_parts = [f"EventID={event_id}", f"Source={source}"]
            if event_data:
                for k, v in event_data.items():
                    message_parts.append(f"{k}={v}")
            message = " | ".join(message_parts)

            raw = ET.tostring(elem, encoding="unicode")

            return WindowsEventEntry(
                event_id=event_id,
                timestamp=timestamp,
                level=level,
                channel=channel,
                computer=computer,
                user=user,
                message=message,
                source=source,
                raw=raw,
                event_data=event_data,
            )
        except (AttributeError, ValueError, KeyError):
            return None

    def parse_file(self, filepath: str) -> Iterator[WindowsEventEntry]:
        """
        Dosya uzantısına göre uygun parser'ı seçer.

        Args:
            filepath: Log dosyası yolu

        Yields:
            WindowsEventEntry nesneleri
        """
        if filepath.lower().endswith(".xml"):
            yield from self.parse_xml_file(filepath)
        else:
            # Düz metin formatı - basit pattern matching
            yield from self._parse_text_file(filepath)

    def _parse_text_file(self, filepath: str) -> Iterator[WindowsEventEntry]:
        """Basit metin formatındaki Windows log dosyalarını parse eder."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            buffer = []
            for line in fh:
                line = line.strip()
                if line.startswith("Event ID:") and buffer:
                    entry = self._parse_text_block(buffer)
                    if entry:
                        yield entry
                    buffer = []
                buffer.append(line)
            if buffer:
                entry = self._parse_text_block(buffer)
                if entry:
                    yield entry

    def _parse_text_block(self, lines: list) -> Optional[WindowsEventEntry]:
        """Metin bloğundan WindowsEventEntry oluşturur."""
        data = {}
        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                data[key.strip()] = value.strip()

        try:
            event_id = int(data.get("Event ID", "0"))
            timestamp_str = data.get("Date and Time", "")
            try:
                timestamp = datetime.strptime(timestamp_str, "%m/%d/%Y %I:%M:%S %p")
            except ValueError:
                timestamp = datetime.now()

            return WindowsEventEntry(
                event_id=event_id,
                timestamp=timestamp,
                level=data.get("Level", "Information").upper(),
                channel=data.get("Log Name", "System"),
                computer=data.get("Computer", "Unknown"),
                user=data.get("User", "N/A"),
                message=data.get("Description", ""),
                source=data.get("Source", "Unknown"),
                raw="\n".join(lines),
            )
        except (ValueError, KeyError):
            return None
