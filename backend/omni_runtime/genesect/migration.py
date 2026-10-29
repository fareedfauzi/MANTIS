"""Opt-in, non-destructive migration from legacy installs."""

import configparser
import os

LEGACY_PREFIX = "pseudo" + "note"
LEGACY_NETNODE = "$ " + LEGACY_PREFIX + ":readable_c"
LEGACY_KB_NETNODE = "$ " + LEGACY_PREFIX + ":agent_kb"
LEGACY_FLOSS_NETNODE = "$ " + LEGACY_PREFIX + ":floss_results"
MIGRATABLE_TAGS = (0, 78, 79, 80, 81, 83, 84, 85, 86, 87, 88, 89, 90, 91, 97)


def merge_ini_non_destructive(source_path, target_path):
    """Copy missing INI options while preserving both source and existing target values."""
    if not source_path or not os.path.isfile(source_path):
        return {"copied": 0, "skipped": 0, "source_missing": True}
    source, target = configparser.ConfigParser(), configparser.ConfigParser()
    source.read(source_path, encoding="utf-8")
    if os.path.isfile(target_path):
        target.read(target_path, encoding="utf-8")
    copied = skipped = 0
    for section in source.sections():
        if not target.has_section(section):
            target.add_section(section)
        for key, value in source.items(section):
            if target.has_option(section, key):
                skipped += 1
            else:
                target.set(section, key, value)
                copied += 1
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    temporary = target_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        target.write(stream)
    os.replace(temporary, target_path)
    return {"copied": copied, "skipped": skipped, "source_missing": False}


def migrate_legacy_idb():
    """Copy known legacy blobs only when the extended destination is empty."""
    import ida_funcs
    import ida_kernwin
    import ida_netnode
    from genesect.idb_storage import get_kb_netnode, get_netnode

    legacy = ida_netnode.netnode(LEGACY_NETNODE, 0, False)
    target = get_netnode(create=True)
    copied = skipped = 0
    if legacy and legacy != ida_netnode.BADNODE and target:
        ea = ida_funcs.get_next_func(0)
        while ea:
            func_ea = ea.start_ea
            for tag in MIGRATABLE_TAGS:
                old = legacy.getblob(func_ea, tag)
                if not old:
                    continue
                if target.getblob(func_ea, tag):
                    skipped += 1
                else:
                    target.setblob(old, func_ea, tag)
                    copied += 1
            ea = ida_funcs.get_next_func(func_ea)

    # Knowledge-base blobs use sparse indices; preserve destination entries.
    legacy_kb = ida_netnode.netnode(LEGACY_KB_NETNODE, 0, False)
    target_kb = get_kb_netnode(create=True)
    if legacy_kb and legacy_kb != ida_netnode.BADNODE and target_kb:
        idx = legacy_kb.supfirst()
        while idx != ida_netnode.BADNODE:
            old = legacy_kb.getblob(idx, 0)
            if old:
                if target_kb.getblob(idx, 0):
                    skipped += 1
                else:
                    target_kb.setblob(old, idx, 0)
                    copied += 1
            idx = legacy_kb.supnxt(idx)
    ida_kernwin.msg(f"[Genesect] Migration copied {copied} artifacts; preserved {skipped} existing artifacts.\n")
    return copied, skipped


def migrate_legacy_config(target_path):
    candidates = [
        os.path.join(os.path.expanduser("~"), "." + LEGACY_PREFIX + ".ini"),
        os.path.join(os.path.dirname(target_path), "Genesect.ini"),
    ]
    total = {"copied": 0, "skipped": 0}
    for source in candidates:
        result = merge_ini_non_destructive(source, target_path)
        total["copied"] += result["copied"]
        total["skipped"] += result["skipped"]
    return total


class LegacyMigrationHandler:
    """Factory-backed handler to avoid importing IDA during standalone tests."""
    @staticmethod
    def create():
        import idaapi
        import ida_kernwin
        from genesect.config import CONFIG

        class Handler(idaapi.action_handler_t):
            def activate(self, ctx):
                prompt = (
                    "Copy missing data from the legacy plugin into Genesect?\n\n"
                    "Existing Genesect values will not be overwritten. Legacy netnodes and configuration files will not be modified or deleted."
                )
                if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, prompt) != ida_kernwin.ASKBTN_YES:
                    return 0
                copied, skipped = migrate_legacy_idb()
                cfg = migrate_legacy_config(CONFIG.user_config_path)
                ida_kernwin.info(f"Migration complete.\n\nIDB copied: {copied}\nIDB preserved: {skipped}\nConfig options copied: {cfg['copied']}")
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS
        return Handler()
