ACCOUNT_FILES = ("passwd", "shadow", "group", "gshadow", "subuid", "subgid")
ACCOUNT_BACKUP_SUFFIXES = ("-", "~", ".bak", ".old", ".orig", ".save")
HISTORY_FILES = (
    "/root/.bash_history", "/root/.ash_history", "/root/.zsh_history",
    "/root/.python_history", "/root/.mysql_history", "/root/.sqlite_history",
    "/root/.history", "/root/.lesshst", "/root/.local/share/fish/fish_history",
)
CREDENTIAL_DIRECTORIES = ("/root/.ssh",)
CREDENTIAL_PATHS = (
    *(f"/etc/{name}{suffix}" for name in ACCOUNT_FILES for suffix in ACCOUNT_BACKUP_SUFFIXES),
    *(f"/var/backups/{name}*" for name in ACCOUNT_FILES),
    *CREDENTIAL_DIRECTORIES,
    *HISTORY_FILES,
)
