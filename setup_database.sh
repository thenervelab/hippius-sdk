#!/bin/bash
# Database setup script for Hippius key storage

set -e

echo "🗄️  Setting up Hippius key storage database..."

# Load database URL from env file
source .env.db

echo "📊 Database URL: $DATABASE_URL"

# Create database if it doesn't exist
echo "📝 Creating database hippius_keys..."
PGPASSWORD=postgres createdb -h localhost -U postgres hippius_keys 2>/dev/null || echo "Database hippius_keys already exists"

# Run migrations with dbmate
echo "🚀 Running database migrations..."
if command -v dbmate &> /dev/null; then
    dbmate up
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
source venv/bin/activate
python -c "
from hippius_sdk.config import set_config_value
set_config_value('key_storage', 'database_url', 'postgresql://postgres:postgres@localhost:5432/hippius_keys?sslmode=disable')
set_config_value('key_storage', 'enabled', True)
print('✅ Hippius SDK configured for key storage')
"

echo "🎉 Setup complete! Key storage is ready to use."
echo ""
echo "📋 What was set up:"
echo "   - Database: hippius_keys"
echo "   - Tables: seed_phrases, encryption_keys"
echo "   - SDK config: key_storage enabled"
echo ""
echo "🧪 Test with: python test_key_storage.py"