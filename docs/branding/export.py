"""Export local artwork and outlined lettering; --check compares without writing."""

import argparse
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

import resvg_py
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent
NS = "{http://www.w3.org/2000/svg}"
PALETTES = {
    "light": ("#f7f5f0", "#18383d", "#146b73", "#ce992c"),
    "dark": ("#18383d", "#f7f5f0", "#7ac2c6", "#e1b451"),
}


def lettering(font, value, x, y, size, color):
    """Use paths so a viewer needs neither an installed nor a remote font."""
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    paths = []
    for char in value:
        glyph = cmap[ord(char)]
        pen = SVGPathPen(glyphs, ntos=lambda n: f"{n:.2f}")
        glyphs[glyph].draw(pen)
        paths.append(f'<path transform="translate({x:.3f} {y}) scale({scale:.6f} {-scale:.6f})" d="{pen.getCommands()}"/>')
        x += font["hmtx"][glyph][0] * scale
    return f'<g fill="{color}">' + "".join(paths) + "</g>"


def svg(width, height, title, body, background=None):
    backdrop = f'<rect width="{width}" height="{height}" fill="{background}"/>' if background else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title">\n'
            f'<title id="title">{escape(title)}</title>\n{backdrop}{body}\n</svg>\n').encode()


def outputs():
    symbol = ET.parse(ROOT / "symbol.svg").getroot()
    geometry = "".join(ET.tostring(child, encoding="unicode") for child in symbol)
    features = list(ET.parse(ROOT / "features.svg").getroot().find(NS + "defs"))
    font_path = ROOT / "fonts/Outfit.ttf"
    bold = instantiateVariableFont(TTFont(font_path), {"wght": 600})
    regular = instantiateVariableFont(TTFont(font_path), {"wght": 400})

    def mark(x, y, size, theme, mono=False):
        source = geometry
        _, ink, teal, ochre = PALETTES[theme]
        # Replace simultaneously: the dark background also equals the light ink.
        colors = {"#18383d": ink, "#146b73": ink if mono else teal, "#ce992c": ink if mono else ochre}
        for index, old in enumerate(colors):
            source = source.replace(old, f"COLOR_{index}")
        for index, color in enumerate(colors.values()):
            source = source.replace(f"COLOR_{index}", color)
        return f'<g transform="translate({x} {y}) scale({size / 128})">{source}</g>'

    def icon(index, x, y, size, ink):
        shape = "".join(ET.tostring(child, encoding="unicode") for child in features[index])
        return (f'<g transform="translate({x} {y}) scale({size / 24})" fill="none" '
                f'stroke="{ink}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{shape}</g>')

    def illustration(x, y, theme):
        _, ink, teal, ochre = PALETTES[theme]
        body = f'<path d="M0 82H238" fill="none" stroke="{ink}" stroke-width="2"/>'
        for index, center in enumerate((36, 118, 200)):
            body += icon(index, center - 24, 12, 48, ink)
            body += f'<path d="M{center} 62V82" stroke="{ink}" stroke-width="2"/>'
            body += f'<circle cx="{center}" cy="82" r="5" fill="{teal}"/>'
        body += f'<circle cx="238" cy="82" r="5" fill="{ochre}"/>'
        return f'<g transform="translate({x} {y})">{body}</g>'

    result = {}
    for theme, (bg, ink, _, _) in PALETTES.items():
        result[f"symbol-{theme}.svg"] = svg(128, 128, "mcp-unifi-rs", mark(0, 0, 128, theme))
        wordmark = mark(8, 8, 96, theme) + lettering(bold, "mcp-unifi-rs", 128, 76, 58, ink)
        result[f"wordmark-{theme}.svg"] = svg(480, 112, "mcp-unifi-rs", wordmark, bg)
        header = mark(24, 32, 116, theme) + lettering(bold, "mcp-unifi-rs", 164, 91, 58, ink)
        header += lettering(regular, "MCP for UniFi Network & Protect", 164, 128, 24, ink)
        header += illustration(675, 36, theme)
        result[f"header-{theme}.svg"] = svg(960, 180, "mcp-unifi-rs — MCP for UniFi Network & Protect", header, bg)
        avatar = svg(256, 256, "mcp-unifi-rs", mark(48, 48, 160, theme), bg)
        result[f"avatar-{theme}.svg"] = avatar
        result[f"avatar-{theme}.png"] = resvg_py.svg_to_bytes(svg_string=avatar.decode(), skip_system_fonts=True)
    result["symbol-mono.svg"] = svg(128, 128, "mcp-unifi-rs", mark(0, 0, 128, "light", mono=True))
    bg, ink, _, _ = PALETTES["light"]
    social = mark(68, 68, 144, "light") + lettering(bold, "mcp-unifi-rs", 252, 166, 86, ink)
    social += lettering(regular, "MCP for UniFi Network & Protect", 76, 292, 42, ink)
    social += '<g transform="translate(325 330) scale(2.6)">' + illustration(0, 0, "light") + "</g>"
    result["social-preview.svg"] = svg(1280, 640, "mcp-unifi-rs — MCP for UniFi Network & Protect", social, bg)
    result["social-preview.png"] = resvg_py.svg_to_bytes(svg_string=result["social-preview.svg"].decode(), skip_system_fonts=True)
    sheet = ""
    for index, feature in enumerate(features):
        name = feature.attrib["id"]
        result[f"{name}.svg"] = svg(24, 24, name.capitalize(), icon(index, 0, 0, 24, "currentColor"))
        sheet += icon(index, 52 + index * 190, 24, 64, ink)
        sheet += lettering(regular, name.capitalize(), 24 + index * 190, 128, 22, ink)
    result["feature-icons.svg"] = svg(780, 160, "Network, wireless, camera and configuration", sheet, bg)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare exports without writing")
    args = parser.parse_args()
    assets = {ROOT / "assets" / name: data for name, data in outputs().items()}
    if args.check:
        changed = [path.name for path, data in assets.items() if not path.is_file() or path.read_bytes() != data]
        if changed:
            raise SystemExit("Outdated branding exports: " + ", ".join(changed))
        print("Branding exports match their sources.")
    else:
        for path, data in assets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print("Exported branding assets.")


if __name__ == "__main__":
    main()
