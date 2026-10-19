"""Log parsers for various formats."""

from src.parsers.nginx import NginxParser, LogEntry
from src.parsers.apache import ApacheParser
from src.parsers.syslog import SyslogParser
from src.parsers.windows import WindowsEventParser

PARSER_REGISTRY: dict[str, type] = {
    "nginx": NginxParser,
    "apache": ApacheParser,
    "syslog": SyslogParser,
    "windows": WindowsEventParser,
}


def get_parser(name: str):
    """Get a parser instance by name."""
    parser_class = PARSER_REGISTRY.get(name.lower())
    if parser_class is None:
        raise ValueError(f"Unknown parser: {name}. Available: {list(PARSER_REGISTRY.keys())}")
    return parser_class()


__all__ = [
    "LogEntry", "NginxParser", "ApacheParser", "SyslogParser",
    "WindowsEventParser", "get_parser", "PARSER_REGISTRY",
]
