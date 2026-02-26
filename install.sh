#!/bin/bash
clear
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install --upgrade --force-reinstall \
  "requests>=2.32.0,<3.0.0" \
  "urllib3>=2.2.0,<3.0.0" \
  "charset_normalizer>=3.3.0,<4.0.0" \
  "chardet>=5.2.0,<6.0.0"
python3 -m pip install --upgrade --upgrade-strategy eager -r requirements.txt
./run.sh
