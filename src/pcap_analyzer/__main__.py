"""Module execution wrapper allowing execution via: python3 -m pcap_analyzer [args]"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
