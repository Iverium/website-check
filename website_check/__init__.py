"""Website check for small businesses, with Dutch reports. https://github.com/Iverium/website-check"""
from ._common import CheckError, format_report
from .check import analyse, check_website, parse_robots

__version__ = "1.0.0"
__all__ = ["CheckError", "analyse", "check_website", "format_report", "parse_robots"]
