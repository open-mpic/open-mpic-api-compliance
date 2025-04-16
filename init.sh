#!/usr/bin/env bash
deactivate
rm -r venv
rm -r open-multi-perspective-issuance-corroboration-ap-iv-2-spec-client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
#openapi-python-client generate --url https://raw.githubusercontent.com/open-mpic/open-mpic-specification/df41f81cbb2d724183f7a81e578d128afdc79b3a/openapi.yaml
openapi-python-client generate --url https://raw.githubusercontent.com/open-mpic/open-mpic-specification/main/openapi.yaml 
cd open-multi-perspective-issuance-corroboration-ap-iv-2-spec-client
poetry build -f wheel
pip install dist/open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client-*-py3-none-any.whl
cd ..
echo "Successfully initiated testing project. Run \"source venv/bin/activate\" to get an env with open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client installed."