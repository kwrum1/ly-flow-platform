"""Optional Python auto-bootstrap for LyFlow RASP.

Enable by placing this package on PYTHONPATH and setting LY_RASP_AUTOLOAD=true.
Invalid policy modes safely fall back to monitor mode in config.normalize_mode.
"""

import os

if os.environ.get("LY_RASP_AUTOLOAD", "false").lower() == "true":
    from ly_rasp import enable

    enable()
