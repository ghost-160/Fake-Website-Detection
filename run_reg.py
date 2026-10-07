import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
with open("test_out.txt", "w", encoding='utf-8') as f:
    orig = sys.stdout
    sys.stdout = f
    import test_regression
    test_regression.test()
    sys.stdout = orig
