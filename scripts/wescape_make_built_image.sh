#!/bin/bash
# Builds the tree of a SEC-bench libredwg image once with `secb build` in a
# fresh container and commits the container as a local image.
# scripts/libredwg_run_variant.sh starts its variant containers from that
# image, so that a variant recompiles only the files its diff changes
# (configure and make find the existing objects) instead of the whole
# library, which takes several minutes under emulation.
#
# Copy of scripts/libredwg_make_built_image.sh for libredwg.cve-2020-21814,
# with one added step: the dataset PoC of the image, /testcase/poc, is also
# copied to /testcase/poc.dwg before the commit. The case `poc` of
# scripts/escape_cases.py (reused unchanged) reads /testcase/poc.dwg, the
# path of the PoC in the image of libredwg.cve-2020-21816; with the copy it
# runs the dataset PoC of the image the built image comes from.
#
# Usage: wescape_make_built_image.sh <image> <tag> <build-log>
#
#   <image>      e.g. hwiwonlee/secb.eval.x86_64.libredwg.cve-2020-21814
#   <tag>        local image name to create, e.g.
#                secb.built.x86_64.libredwg.cve-2020-21814:base
#   <build-log>  receives the header and the output of `secb build`
#
# The container is secb-libredwg-<cve number>-built and is removed after the
# commit. Extra `docker run` options are taken from SECB_DOCKER_OPTS
# (default empty) and printed in the log header.
# shellcheck disable=SC2086
set -eu
image=$1 tag=$2 log=$3
opts=${SECB_DOCKER_OPTS:-}
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-libredwg-$cve-built
# shellcheck disable=SC2086
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
{ echo "--- container $c image $image docker-opts: ${opts:-<none>}"
  echo "--- image id $(docker inspect --format '{{.Id}}' "$image")"
  echo "--- HEAD $(docker exec "$c" git -C /src/libredwg rev-parse HEAD)"
  echo "--- started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker exec "$c" secb build 2>&1
  echo "--- finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker exec "$c" cp /testcase/poc /testcase/poc.dwg
  echo "--- copied /testcase/poc to /testcase/poc.dwg, sha256 $(docker exec "$c" sha256sum /testcase/poc.dwg | cut -c1-64)"
} > "$log"
grep -q 'BUILD COMPLETED SUCCESSFULLY' "$log" || { echo "build failed, see $log" >&2; exit 1; }
docker commit "$c" "$tag" >/dev/null
echo "committed $tag $(docker inspect --format '{{.Id}}' "$tag")"
