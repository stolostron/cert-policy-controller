import json
import sys
import os
from subprocess import run

data = json.load(open(sys.argv[1]))
for v in data:
    component_name = v["name"]
    compenent_tag = v["tag"]
    compenent_sha = v["sha256"]
    component_repo = v["repository"]
    component_version = v["tag"].replace('-'+v["sha256"],'')
    retag_name = component_version + "-SNAPSHOT-" + sys.argv[2]
    run('echo RETAG_SNAPSHOT_NAME={} COMPONENT_NAME={} RETAG_REPO={} RETAG_QUAY_COMPONENT_TAG={} RETAG_GITHUB_SHA={} RETAG_DRY_RUN={}'.format(retag_name, component_repo, component_name, compenent_tag, compenent_sha, sys.argv[3]), shell=True)
    run('make retag/git RETAG_SNAPSHOT_NAME={} RETAG_REPO={} RETAG_QUAY_COMPONENT_TAG={} RETAG_GITHUB_SHA={} RETAG_DRY_RUN={}'.format(retag_name, component_repo, compenent_tag, compenent_sha, sys.argv[3]), shell=True, check=True)
    run('make retag/quay RETAG_SNAPSHOT_NAME={} COMPONENT_NAME={} RETAG_QUAY_COMPONENT_TAG={} RETAG_GITHUB_SHA={} RETAG_DRY_RUN={}'.format(retag_name, component_name, compenent_tag, compenent_sha, sys.argv[3]), shell=True, check=True)
