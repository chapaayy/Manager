"""Independent file library and reusable multi-file presets. No VPN projects."""
from __future__ import annotations

import sqlite3
import time
import uuid

from . import storage

KINDS = ("xray", "nginx", "nginx_compose", "node_compose")


def validate_file(name: str, kind: str, content: str):
    if kind not in KINDS:
        raise ValueError("Неподдерживаемый тип файла")
    if not name.strip() or len(name.strip()) > 100:
        raise ValueError("Укажи название конфигурации, до 100 символов")
    if not content.strip() or len(content.encode()) > 250000 or "\x00" in content:
        raise ValueError("Конфиг должен содержать 1–250 КБ текста без NUL")
    # JSON templates with {{variables}} remain valid JSON string values.
    if kind == "xray":
        import json
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError("Некорректный JSON: " + str(e)) from None
        if not isinstance(parsed, dict):
            raise ValueError("Xray должен быть JSON-объектом")


def config_view(row, include_content: bool = False):
    result = {key: row[key] for key in ("id", "name", "kind", "revision", "created_at", "updated_at")}
    if include_content:
        result["content"] = storage.decrypt(row["content_enc"])
    return result


def list_files():
    with storage.connect() as c:
        return [config_view(r) for r in c.execute(
            "SELECT * FROM library_configs ORDER BY kind,name COLLATE NOCASE").fetchall()]


def get_file(file_id: str):
    with storage.connect() as c:
        row = c.execute("SELECT * FROM library_configs WHERE id=?", (file_id,)).fetchone()
    if not row:
        raise LookupError("Файл конфигурации не найден")
    return config_view(row, True)


def save_file(*, name: str, kind: str, content: str, file_id: str = "",
              revision: int | None = None):
    validate_file(name, kind, content)
    now = int(time.time())
    ident = file_id or str(uuid.uuid4())
    with storage.transaction() as c:
        if file_id:
            previous = c.execute("SELECT kind,revision FROM library_configs WHERE id=?",
                                 (file_id,)).fetchone()
            if not previous:
                raise LookupError("Файл не найден")
            if previous["kind"] != kind or previous["revision"] != revision:
                raise ValueError("Файл изменился в другой вкладке или сменил тип. Обнови страницу.")
            c.execute("UPDATE library_configs SET name=?,content_enc=?,revision=revision+1,updated_at=? WHERE id=?",
                      (name.strip(), storage.encrypt(content), now, file_id))
        else:
            c.execute("""INSERT INTO library_configs
                         (id,name,kind,content_enc,created_at,updated_at) VALUES(?,?,?,?,?,?)""",
                      (ident, name.strip(), kind, storage.encrypt(content), now, now))
        row = c.execute("SELECT * FROM library_configs WHERE id=?", (ident,)).fetchone()
        storage.event(c, "config.save", ident, "Saved encrypted library file")
    return config_view(row)


def delete_file(file_id: str):
    with storage.transaction() as c:
        if c.execute("SELECT 1 FROM preset_items WHERE config_id=?", (file_id,)).fetchone():
            raise ValueError("Файл используется в пресете. Сначала исключи его из набора.")
        if c.execute("DELETE FROM library_configs WHERE id=?", (file_id,)).rowcount != 1:
            raise LookupError("Файл не найден")
        storage.event(c, "config.delete", file_id, "Deleted library file")
    return {"ok": True}


def preset_view(c, row):
    items = [dict(x) for x in c.execute(
        """SELECT i.kind,c.id AS config_id,c.name AS config_name,c.revision
           FROM preset_items i JOIN library_configs c ON i.config_id=c.id
           WHERE i.preset_id=? ORDER BY i.kind""", (row["id"],)).fetchall()]
    return {**dict(row), "items": items}


def list_presets():
    with storage.connect() as c:
        return [preset_view(c, r) for r in c.execute(
            "SELECT * FROM presets ORDER BY updated_at DESC").fetchall()]


def save_preset(*, name: str, description: str = "", config_ids: list[str],
                preset_id: str = "", mode: str = "custom"):
    if mode not in ("direct","custom"):
        raise ValueError("Неизвестное назначение пресета")
    if not 1 <= len(name.strip()) <= 100 or len(description) > 600:
        raise ValueError("Название 1–100, описание до 600 символов")
    if not 1 <= len(config_ids) <= 4 or len(config_ids) != len(set(config_ids)):
        raise ValueError("Выбери от одного до четырёх разных файлов")
    now = int(time.time())
    ident = preset_id or str(uuid.uuid4())
    with storage.transaction() as c:
        types = set()
        selected = []
        for file_id in config_ids:
            row = c.execute("SELECT id,kind FROM library_configs WHERE id=?",
                            (file_id,)).fetchone()
            if not row:
                raise LookupError("В пресете есть неизвестный файл")
            if row["kind"] in types:
                raise ValueError("Пресет может содержать только один файл каждого типа")
            types.add(row["kind"])
            selected.append(row)
        if mode == "direct" and "xray" not in types:
            raise ValueError("Для установочного пресета нужен Xray JSON")
        if preset_id:
            if c.execute("UPDATE presets SET name=?,description=?,mode=?,updated_at=? WHERE id=?",
                         (name.strip(), description.strip(), mode, now, ident)).rowcount != 1:
                raise LookupError("Пресет не найден")
            c.execute("DELETE FROM preset_items WHERE preset_id=?", (ident,))
        else:
            c.execute("INSERT INTO presets(id,name,description,mode,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                      (ident, name.strip(), description.strip(), mode, now, now))
        for row in selected:
            c.execute("INSERT INTO preset_items(preset_id,config_id,kind) VALUES(?,?,?)",
                      (ident, row["id"], row["kind"]))
        result = preset_view(c, c.execute("SELECT * FROM presets WHERE id=?", (ident,)).fetchone())
        storage.event(c, "preset.save", ident, "Saved named file bundle")
    return result


def delete_preset(preset_id: str):
    with storage.transaction() as c:
        if c.execute("DELETE FROM presets WHERE id=?", (preset_id,)).rowcount != 1:
            raise LookupError("Пресет не найден")
        storage.event(c, "preset.delete", preset_id, "Removed preset; files kept")
    return {"ok": True}
