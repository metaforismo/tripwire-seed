#!/usr/bin/env python3
"""Run the reproduction-helper regression suite."""

import unittest
from test_reproduction_boundaries import ReproductionBoundaryTests
from test_reproduction_core import ReproductionCoreTests
from test_reproduction_rejections import ReproductionRejectionTests

if __name__ == "__main__":
    unittest.main()
