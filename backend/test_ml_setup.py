#!/usr/bin/env python3
"""
Test script to verify ML packages are working correctly
"""

def test_ml_packages():
    """Test that all ML packages can be imported and basic functionality works"""
    
    print("🔍 Testing ML Package Installation...")
    print("=" * 50)
    
    # Test imports
    try:
        import sklearn
        print(f"✅ scikit-learn {sklearn.__version__} imported successfully")
    except ImportError as e:
        print(f"❌ scikit-learn import failed: {e}")
        return False
    
    try:
        import pandas as pd
        print(f"✅ pandas {pd.__version__} imported successfully")
    except ImportError as e:
        print(f"❌ pandas import failed: {e}")
        return False
    
    try:
        import numpy as np
        print(f"✅ numpy {np.__version__} imported successfully")
    except ImportError as e:
        print(f"❌ numpy import failed: {e}")
        return False
    
    try:
        import joblib
        print(f"✅ joblib {joblib.__version__} imported successfully")
    except ImportError as e:
        print(f"❌ joblib import failed: {e}")
        return False
    
    # Test basic functionality
    print("\n🧪 Testing Basic Functionality...")
    print("-" * 30)
    
    try:
        # Test numpy
        arr = np.array([1, 2, 3, 4, 5])
        print(f"✅ Numpy array creation: {arr}")
        
        # Test pandas
        df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
        print(f"✅ Pandas DataFrame creation: {df.shape} shape")
        
        # Test sklearn
        from sklearn.ensemble import RandomForestClassifier
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        print("✅ Random Forest classifier created")
        
        # Test basic ML workflow
        X = np.array([[1, 2], [3, 4], [5, 6], [7, 8]])
        y = np.array([0, 1, 0, 1])
        rf.fit(X, y)
        prediction = rf.predict([[2, 3]])
        print(f"✅ ML prediction test: {prediction[0]}")
        
    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        return False
    
    print("\n🎉 All tests passed! ML environment is ready.")
    print("\nYou can now run:")
    print("1. python manage.py train_ml_models --dataset-path kdd_test.csv")
    print("2. python manage.py process_ml_threats")
    print("3. python manage.py parse_snort_logs --file alerts.csv")
    
    return True

if __name__ == "__main__":
    test_ml_packages()
