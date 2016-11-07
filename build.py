import os
import time
import sys
import shutil

try:

  # Add extra obfuscation
  key = "test-test-test" % (int(time.time()) - 92834877)
  cmd = "pyinstaller \"mare-detector.py\" -F -n mare-detector-%s --distpath \"dist\" --specpath \"spec\" --key \"%s\" --clean\n" % ("0.2.2", key)
  os.system(cmd)

  # Pause
  sys.exit(0)
except Exception as e:
  print "Error building Mare Detector: " + str(e)
sys.exit(0)