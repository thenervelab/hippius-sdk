"""
Database utilities for Hippius SDK key storage.
"""

import shutil
from pathlib import Path


def get_db_path() -> Path:
    """Get the path to the database files."""
    return Path(__file__).parent / "db"


def setup_db_cli() -> None:
    """CLI command to set up database files in current directory."""
    db_path = get_db_path()

    print("🗄️  Setting up Hippius database files...")

    # Copy database files to current directory
    current_dir = Path.cwd()

    # Copy migrations to hippius_s3/sql/sdk_migrations
    migrations_dest = current_dir / "hippius_s3" / "sql" / "sdk_migrations"
    migrations_dest.mkdir(parents=True, exist_ok=True)

    migrations_src = db_path / "migrations"
    if migrations_src.exists():
        for migration_file in migrations_src.glob("*.sql"):
            shutil.copy2(migration_file, migrations_dest)
        print(f"📁 Copied migrations to {migrations_dest}")

    # Copy setup script
    setup_script_src = db_path / "setup_database.sh"
    setup_script_dest = current_dir / "setup_database.sh"
    if setup_script_src.exists():
        shutil.copy2(setup_script_src, setup_script_dest)
        setup_script_dest.chmod(0o755)
        print(f"🔧 Copied setup script to {setup_script_dest}")

    # Copy env template
    env_template_src = db_path / "env.db.template"
    env_template_dest = current_dir / "env.db.template"
    if env_template_src.exists():
        shutil.copy2(env_template_src, env_template_dest)
        print(f"📝 Copied env template to {env_template_dest}")

    print()
    print("✅ Database setup files copied successfully!")
    print()
    print("🚀 Next steps:")
    print(
        "  1. Copy env.db.template to .env.db and edit with your database credentials"
    )
    print("  2. Run: ./setup_database.sh")


if __name__ == "__main__":
    setup_db_cli()
