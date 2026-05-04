from dataclasses import dataclass


@dataclass
class DisplayField:
    label: str
    value: str
    indent: int = 0
