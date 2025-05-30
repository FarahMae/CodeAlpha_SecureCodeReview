#!/bin/bash
echo "🔒 CodeAlpha Task 3: Secure Coding Review Setup"
echo "=============================================="

# Add local bin to PATH for this session
export PATH="$HOME/.local/bin:$PATH"

# Test Bandit installation
echo "🧪 Testing Bandit installation..."
python3 -c "import bandit; print('✅ Bandit imported successfully')"

# Test Flask installation
echo "🧪 Testing Flask installation..."
python3 -c "import flask; print('✅ Flask imported successfully')"

echo "✅ All dependencies working!"
echo ""
echo "🚀 Quick start:"
echo "  1. Run security analysis: cd analysis_tools && python3 security_scanner.py"
echo "  2. Test vulnerable app:   cd vulnerable_apps/python_webapp && python3 app.py"
echo "  3. Test secure app:      cd secure_examples && python3 secure_app.py"
