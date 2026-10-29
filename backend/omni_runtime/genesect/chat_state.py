"""Pure state helpers shared by chat UIs."""


def split_context_blocks(blocks, limit=25000):
    """Pack text blocks into bounded chunks, splitting oversized blocks by lines."""
    limit = max(1000, int(limit))
    pieces = []
    for block in blocks:
        text = str(block or "")
        while len(text) > limit:
            cut = text.rfind("\n", 0, limit + 1)
            if cut < limit // 2:
                cut = limit
            else:
                cut += 1
            pieces.append(text[:cut])
            text = text[cut:]
        if text:
            pieces.append(text)

    chunks = []
    current = ""
    for piece in pieces:
        separator = "\n\n" if current else ""
        if current and len(current) + len(separator) + len(piece) > limit:
            chunks.append(current)
            current = piece
        else:
            current += separator + piece
    if current:
        chunks.append(current)
    return chunks


def selection_signature(addresses):
    return tuple(sorted({int(address) for address in addresses}))


def normalize_chat_history(value, system_prompt=None):
    """Return a safe role/content transcript, optionally forcing its system row."""
    rows = []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            content = item.get("content")
            if role in ("system", "user", "assistant") and isinstance(content, str):
                rows.append({"role": role, "content": content})
    if system_prompt is not None:
        rows = [row for row in rows if row["role"] != "system"]
        rows.insert(0, dict(system_prompt))
    return rows


def build_context_snapshot(blocks, max_chars=120000):
    """Build a deterministic bounded context snapshot from ordered functions."""
    max_chars = max(1000, int(max_chars))
    output = []
    included = 0
    truncated = 0
    used = 0
    for index, block in enumerate(blocks):
        text = str(block or "")
        separator = "\n\n" if output else ""
        remaining = max_chars - used - len(separator)
        if remaining <= 0:
            truncated += len(blocks) - index
            break
        if len(text) <= remaining:
            output.append(separator + text)
            used += len(separator) + len(text)
            included += 1
            continue
        marker = "\n/* Context truncated at configured limit. */"
        take = max(0, remaining - len(marker))
        output.append(separator + text[:take] + marker[:remaining - take])
        used = max_chars
        included += 1
        truncated += len(blocks) - index
        break
    return "".join(output), included, truncated
