"""Generate high-quality notebook screenshots including markdown and outputs."""

from __future__ import annotations

import argparse
import base64
import io
import json
import textwrap
from pathlib import Path
from typing import List, Tuple

from PIL import Image, ImageDraw, ImageFont


def load_fonts(scale: int = 2) -> Tuple[ImageFont.FreeTypeFont, ImageFont.FreeTypeFont]:
    """Load readable Windows fonts with fallback."""
    title_size = 16 * scale
    body_size = 13 * scale
    candidates = [
        ("C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/consola.ttf"),
        ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/consola.ttf"),
    ]
    for title_path, body_path in candidates:
        try:
            return (
                ImageFont.truetype(title_path, title_size),
                ImageFont.truetype(body_path, body_size),
            )
        except OSError:
            continue
    return ImageFont.load_default(), ImageFont.load_default()


def wrap_lines(text: str, width: int) -> List[str]:
    """Wrap text while preserving blank lines."""
    result: List[str] = []
    for raw in text.splitlines() or [""]:
        wrapped = textwrap.wrap(
            raw,
            width=width,
            replace_whitespace=False,
            drop_whitespace=False,
        )
        result.extend(wrapped if wrapped else [""])
    return result


def output_text_from_cell(output: dict) -> str:
    """Extract readable text from notebook output object."""
    output_type = output.get("output_type", "")
    if output_type == "stream":
        text = output.get("text", "")
        return "".join(text) if isinstance(text, list) else str(text)
    if output_type in {"execute_result", "display_data"}:
        data = output.get("data", {})
        text_plain = data.get("text/plain", "")
        return "".join(text_plain) if isinstance(text_plain, list) else str(text_plain)
    if output_type == "error":
        traceback = output.get("traceback", [])
        return "\n".join(traceback) if traceback else str(output.get("evalue", ""))
    return ""


def output_image_from_cell(output: dict) -> Image.Image | None:
    """Extract embedded PNG image from output if present."""
    data = output.get("data", {})
    image_b64 = data.get("image/png")
    if not image_b64:
        return None
    if isinstance(image_b64, list):
        image_b64 = "".join(image_b64)
    raw = base64.b64decode(image_b64)
    return Image.open(io.BytesIO(raw)).convert("RGB")


def draw_text_block(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    lines: List[str],
    font: ImageFont.ImageFont,
    fill: Tuple[int, int, int],
    line_height: int,
) -> int:
    """Draw wrapped lines and return new y position."""
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += line_height
    return y


def render_cell_image(
    cell: dict,
    cell_index: int,
    title_font: ImageFont.ImageFont,
    body_font: ImageFont.ImageFont,
    scale: int,
) -> Image.Image:
    """Render one notebook cell with source and outputs."""
    width = 1600 * scale // 2
    padding = 18 * scale
    line_height = 22 * scale // 2
    source_wrap = 120
    output_wrap = 125

    cell_type = cell.get("cell_type", "unknown")
    source = "".join(cell.get("source", []))
    source_lines = wrap_lines(source, source_wrap)

    output_text_lines: List[str] = []
    output_images: List[Image.Image] = []
    if cell_type == "code":
        for output in cell.get("outputs", []):
            output_text = output_text_from_cell(output)
            if output_text.strip():
                output_text_lines.extend(wrap_lines(output_text, output_wrap))
                output_text_lines.append("")
            out_img = output_image_from_cell(output)
            if out_img is not None:
                output_images.append(out_img)

    source_block_height = max(line_height * (len(source_lines) + 1), line_height * 2)
    output_text_height = line_height * (len(output_text_lines) + 1) if output_text_lines else 0

    image_total_height = (
        padding
        + line_height * 2
        + source_block_height
        + (padding if output_text_lines else 0)
        + output_text_height
        + (padding if output_images else 0)
        + sum(min(img.height, 900) + padding for img in output_images)
        + padding
    )

    canvas = Image.new("RGB", (width, image_total_height), (248, 250, 252))
    draw = ImageDraw.Draw(canvas)

    header = f"Cell {cell_index:03d} [{cell_type}]"
    draw.text((padding, padding), header, font=title_font, fill=(23, 37, 84))

    y = padding + line_height * 2
    source_title = "Source:"
    draw.text((padding, y), source_title, font=title_font, fill=(30, 41, 59))
    y += line_height

    # Source box
    source_box_top = y
    source_box_height = source_block_height
    draw.rectangle(
        (padding - 8, source_box_top - 6, width - padding + 4, source_box_top + source_box_height),
        outline=(203, 213, 225),
        width=1,
        fill=(255, 255, 255),
    )
    y = draw_text_block(
        draw=draw,
        x=padding,
        y=source_box_top + 6,
        lines=source_lines if source_lines else [""],
        font=body_font,
        fill=(17, 24, 39),
        line_height=line_height,
    )

    if output_text_lines or output_images:
        y += padding // 2
        draw.text((padding, y), "Outputs:", font=title_font, fill=(30, 41, 59))
        y += line_height

    if output_text_lines:
        out_box_top = y
        out_box_height = output_text_height
        draw.rectangle(
            (padding - 8, out_box_top - 6, width - padding + 4, out_box_top + out_box_height),
            outline=(203, 213, 225),
            width=1,
            fill=(255, 255, 255),
        )
        y = draw_text_block(
            draw=draw,
            x=padding,
            y=out_box_top + 6,
            lines=output_text_lines,
            font=body_font,
            fill=(8, 47, 73),
            line_height=line_height,
        )

    for out_img in output_images:
        y += padding // 2
        max_w = width - 2 * padding
        if out_img.width > max_w:
            ratio = max_w / out_img.width
            new_size = (max_w, int(out_img.height * ratio))
            out_img = out_img.resize(new_size)
        if out_img.height > 900:
            ratio = 900 / out_img.height
            new_size = (int(out_img.width * ratio), 900)
            out_img = out_img.resize(new_size)
        canvas.paste(out_img, (padding, y))
        y += out_img.height + padding

    # Trim bottom if needed.
    if y + padding < canvas.height:
        canvas = canvas.crop((0, 0, canvas.width, y + padding))

    return canvas


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--notebook", required=True, help="Notebook path")
    parser.add_argument("--out-dir", default="screenshots", help="Output directory")
    parser.add_argument("--scale", type=int, default=2, help="Render scale for better quality")
    args = parser.parse_args()

    notebook_path = Path(args.notebook)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with notebook_path.open("r", encoding="utf-8") as file:
        notebook = json.load(file)

    title_font, body_font = load_fonts(scale=args.scale)

    cells = notebook.get("cells", [])
    saved = 0
    for idx, cell in enumerate(cells, start=1):
        image = render_cell_image(
            cell=cell,
            cell_index=idx,
            title_font=title_font,
            body_font=body_font,
            scale=args.scale,
        )
        out_path = out_dir / f"cell_{idx:03d}_{cell.get('cell_type', 'unknown')}.png"
        image.save(out_path, format="PNG")
        saved += 1

    print(f"Generated {saved} screenshots in '{out_dir}'.")


if __name__ == "__main__":
    main()
