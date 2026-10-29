"""Dependency-free design tokens and palette definitions."""

from dataclasses import dataclass

SPACING = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24, "xxl": 32}
RADIUS = {"sm": 4, "md": 7, "lg": 10}
CONTROL_HEIGHT = {"compact": 26, "normal": 32, "large": 38}
FONT_SIZE = {"caption": 9, "body": 10, "subtitle": 12, "title": 18, "hero": 24}


@dataclass(frozen=True)
class PaletteTokens:
    name: str
    window: str
    surface: str
    surface_alt: str
    surface_hover: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_disabled: str
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_text: str
    success: str
    warning: str
    danger: str
    info: str
    selection: str
    code_background: str

    def as_dict(self):
        return dict(self.__dict__)


DARK = PaletteTokens("dark", "#16181D", "#1E2128", "#252933", "#2C313C", "#343A46", "#495161", "#F2F4F7", "#A9B0BD", "#6F7682", "#4C8DFF", "#6AA0FF", "#3777E3", "#FFFFFF", "#45C47C", "#E6A23C", "#EF6461", "#55B6E8", "#294F86", "#121419")
LIGHT = PaletteTokens("light", "#F4F6F8", "#FFFFFF", "#EEF1F5", "#E5EAF0", "#D4DAE3", "#AEB7C5", "#18202B", "#596474", "#929BA8", "#2563D9", "#3574EB", "#1D4FAF", "#FFFFFF", "#238A52", "#A8660A", "#C53A3A", "#147BA8", "#BDD5FF", "#F8FAFC")


def palette_for_name(name):
    return LIGHT if str(name).lower() == "light" else DARK


def readable_text(background_hex):
    value = background_hex.lstrip("#")
    if len(value) != 6:
        raise ValueError("Expected a six-digit hexadecimal color")
    channels = [int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    luminance = 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    return "#000000" if luminance > 0.45 else "#FFFFFF"
