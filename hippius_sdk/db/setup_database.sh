#!/bin/bash
# Database setup script for Hippius key storage

set -e

echo "🗄️  Setting up Hippius key storage database..."

# Check if .env.db exists, if not create from template
if [ ! -f .env.db ]; then
    if [ -f hippius_sdk/db/env.db.template ]; then
        echo "📋 Creating .env.db from template..."
        cp hippius_sdk/db/env.db.template .env.db
        echo "✏️  Please edit .env.db with your database credentials"
    elif [ -f env.db.template ]; then
        cp env.db.template .env.db
        echo "✏️  Please edit .env.db with your database credentials"
    else
        echo "❌ No .env.db file found and no template available"
        echo "Please create .env.db with your database connection parameters:"
        echo "DB_HOST=localhost"
        echo "DB_PORT=5432"
        echo "DB_USER=postgres"
        echo "DB_PASSWORD=your_password"
        echo "DB_NAME=hippius_keys"
        echo "DB_SSLMODE=disable"
        exit 1
    fi
fi

# Load database connection parameters from env file
source .env.db

echo "📊 Database connection details:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  User: $DB_USER"
echo "  Database: $DB_NAME"
echo "  SSL Mode: $DB_SSLMODE"

# Construct DATABASE_URL for dbmate
export DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=$DB_SSLMODE"

# Create database if it doesn't exist
echo "📝 Creating database $DB_NAME..."
PGPASSWORD=$DB_PASSWORD createdb -h $DB_HOST -p $DB_PORT -U $DB_USER $DB_NAME 2>/dev/null || echo "Database $DB_NAME already exists"

# Run migrations with dbmate
echo "🚀 Running database migrations..."
if command -v dbmate &> /dev/null; then
    # Use explicit --migrations-dir flag to override any config
    echo "📁 Using migrations from: $(pwd)/hippius_s3/sql/sdk_migrations"
    dbmate --migrations-dir="hippius_s3/sql/sdk_migrations" up
    echo "✅ Database migrations completed successfully!"
else
    echo "❌ dbmate not found. Please install it first:"
    echo "   brew install dbmate"
    echo "   # or"
    echo "   curl -fsSL -o /usr/local/bin/dbmate https://github.com/amacneil/dbmate/releases/latest/download/dbmate-linux-amd64"
    echo "   chmod +x /usr/local/bin/dbmate"
    exit 1
fi

# Configure Hippius SDK to use the database
echo "⚙️  Configuring Hippius SDK..."
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
    python -c "
from hippius_sdk.config import set_config_value
set_config_value('key_storage', 'database_url', '$DATABASE_URL')
set_config_value('key_storage', 'enabled', True)
print('✅ Hippius SDK configured for key storage')
"
else
    echo "⚠️  No virtual environment found. Please configure manually:"
    echo "hippius config set key_storage database_url '$DATABASE_URL'"
    echo "hippius config set key_storage enabled true"
fi

echo "🎉 Setup complete! Key storage is ready to use."
echo ""
echo "📋 What was set up:"
echo "   - Database: hippius_keys"
echo "   - Tables: seed_phrases, encryption_keys"
echo "   - SDK config: key_storage enabled"
echo ""
echo "🧪 Test with: python test_key_storage.py"