# Database Migrations for Hippius Key Storage

This directory contains database migrations for the Hippius SDK key storage feature.

## Setup for End Users

If you've installed hippius-sdk as a dependency, you can set up the database files in your project:

```bash
# Copy database files to your project
hippius-setup-db

# Edit the database URL
cp env.db.template .env.db
# Edit .env.db with your database credentials

# Run the setup
./setup_database.sh
```

## Development Setup

1. **Install dbmate**:
   ```bash
   brew install dbmate
   # or download directly
   curl -fsSL -o /usr/local/bin/dbmate https://github.com/amacneil/dbmate/releases/latest/download/dbmate-macos-amd64
   chmod +x /usr/local/bin/dbmate
   ```

2. **Run the setup script**:
   ```bash
   ./setup_database.sh
   ```

## Manual Setup

If you prefer to run migrations manually:

```bash
# Set database URL
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/hippius_keys?sslmode=disable

# Create database
createdb hippius_keys

# Run migrations
dbmate up

# Configure SDK
hippius config set key_storage database_url "postgresql://postgres:postgres@localhost:5432/hippius_keys?sslmode=disable"
hippius config set key_storage enabled true
```

## Database Schema

### Tables

- **`seed_phrases`**: Stores hashed seed phrases with base64 encoded values
- **`encryption_keys`**: Stores versioned encryption keys per seed phrase (never deleted)

### Key Features

- **Versioned keys**: New keys create new rows, old keys are never deleted
- **Efficient lookups**: Index on `(seed_hash, created_at DESC)` for fast retrieval of latest key
- **Secure storage**: Seed phrases are hashed for indexing, stored base64 encoded
- **Foreign key constraints**: Ensures data integrity between tables

## Migration Commands

```bash
# Check migration status
dbmate status

# Create new migration
dbmate new migration_name

# Run migrations
dbmate up

# Rollback last migration
dbmate down

# Reset database (drop and recreate)
dbmate drop && dbmate up
```