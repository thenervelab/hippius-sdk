# GitHub Actions Workflows for Hippius

This directory contains GitHub Actions workflows for testing and publishing the Hippius package.

## Workflows

### 1. Python Package (`python-package.yml`)

This workflow handles:
- Running tests on multiple Python versions (3.8, 3.9, 3.10)
- Publishing to PyPI when a new release is created

**Triggers:**
- Push to main/master branches
- Pull requests to main/master branches
- Release creation (for publishing to PyPI)

### 2. Publish to TestPyPI (`publish-test-pypi.yml`)

This workflow handles:
- Running tests
- Publishing to TestPyPI

**Triggers:**
- Push to dev/develop/development branches
- Manual trigger via GitHub UI (workflow_dispatch)

## Setup Required

### Setting up API Tokens

Before these workflows will work properly, you need to add the following secrets to your GitHub repository:

1. For PyPI publishing:
   - Go to your GitHub repository → Settings → Secrets → Actions → New repository secret
   - Name: `PYPI_API_TOKEN`
   - Value: Your PyPI API token (get it from https://pypi.org/manage/account/token/)

2. For TestPyPI publishing:
   - Go to your GitHub repository → Settings → Secrets → Actions → New repository secret
   - Name: `TEST_PYPI_API_TOKEN`
   - Value: Your TestPyPI API token (get it from https://test.pypi.org/manage/account/token/)

### Creating a Release

To publish to PyPI:
1. Go to your GitHub repository
2. Click "Releases" on the right sidebar
3. Click "Create a new release"
4. Choose a tag version (e.g., v0.1.0)
5. Add a title and description
6. Click "Publish release"

The workflow will automatically run tests and publish to PyPI if all tests pass.

### Manual TestPyPI Publishing

To manually trigger TestPyPI publishing:
1. Go to your GitHub repository
2. Click "Actions" tab
3. Select "Publish to TestPyPI" workflow
4. Click "Run workflow" dropdown
5. Select the branch and click "Run workflow"

## Troubleshooting

If the publishing step fails, check:
1. That you've set up the correct secrets in your repository
2. That the version in pyproject.toml is incremented (PyPI won't allow publishing the same version twice)
3. The GitHub Actions logs for specific error messages 