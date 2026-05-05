from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    name: str
    target: str
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "OK"

    @property
    def check_id(self) -> str:
        return f"{self.name}.{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "details": self.details,
        }
