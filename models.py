from dataclasses import dataclass, asdict
from typing import Dict


SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
