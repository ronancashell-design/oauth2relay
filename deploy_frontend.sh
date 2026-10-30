#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Fijomi Systems SL
#
# Deploy the OAUTH2Relay website (web/) to S3 and invalidate the CloudFront cache.
#
# Usage:
#   ./deploy_frontend.sh [--dryrun] [--delete] [--no-wait] [--release VERSION]
#
# After the files are uploaded, the CloudFront distribution is invalidated
# (/*) and the script waits until the invalidation has completed.
#
# Options:
#   --dryrun           Show what would be uploaded without changing anything.
#   --delete           Also remove files from the bucket that no longer exist
#                      in web/. Never touches downloads/.
#   --no-wait          Create the invalidation but don't wait for it to complete.
#   --release VERSION  Also upload the release archives and SHA256SUMS from
#                      dist/ (make release VERSION=...) to downloads/vVERSION/.
#
# Environment overrides:
#   BUCKET           S3 bucket name            (default: oauth2relay.com)
#   DISTRIBUTION_ID  CloudFront distribution   (default: ETF345JBQVSEH)
#   AWS_REGION       Bucket region             (default: eu-west-1)
#   AWS_PROFILE      Standard AWS CLI profile selection is honoured.
#   GO_IMPORT_REPO   Git URL the go-import pages point to (default: the
#                    public GitHub repository).
#
# The script also publishes the go-import pages that let the go command
# resolve oauth2relay.com/oauth2relay/v2 (see "Go module pages" below). It
# needs Go installed to list the module's packages.

set -euo pipefail

BUCKET="${BUCKET:-oauth2relay.com}"
DISTRIBUTION_ID="${DISTRIBUTION_ID:-ETF345JBQVSEH}"
AWS_REGION="${AWS_REGION:-eu-west-1}"
GO_IMPORT_REPO="${GO_IMPORT_REPO:-https://github.com/ronancashell-design/oauth2relay}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/web"

DRYRUN=""
DELETE=""
WAIT="yes"
RELEASE=""
DIST_DIR="${SCRIPT_DIR}/dist"
for arg in "$@"; do
  case "$arg" in
    --dryrun) DRYRUN="--dryrun" ;;
    --delete) DELETE="--delete" ;;
    --no-wait) WAIT="" ;;
    --release) EXPECT_RELEASE="yes" ;;
    -h|--help) sed -n '5,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      if [ -n "${EXPECT_RELEASE:-}" ] && [ -z "${RELEASE}" ]; then
        RELEASE="${arg#v}"
      else
        echo "Unknown option: $arg" >&2; exit 1
      fi ;;
  esac
done
if [ -n "${EXPECT_RELEASE:-}" ] && [ -z "${RELEASE}" ]; then
  echo "Error: --release needs a version, e.g. --release 2.1.0" >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "Error: the AWS CLI is not installed." >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "Error: Go is not installed; it is needed to list the packages for the go-import pages." >&2
  exit 1
fi
if [ ! -f "${SOURCE_DIR}/index.html" ]; then
  echo "Error: ${SOURCE_DIR}/index.html not found." >&2
  exit 1
fi

echo "Deploying ${SOURCE_DIR} -> s3://${BUCKET} (${AWS_REGION})${DRYRUN:+ [dry run]}"
aws sts get-caller-identity --query Arn --output text

# Release archives first, so the download links work as soon as the new
# pages are live. Versioned files never change, so they are cached for a
# year. Content types are set explicitly: a guessed gzip encoding would make
# browsers unpack the .tar.gz files and break their checksums.
if [ -n "${RELEASE}" ]; then
  shopt -s nullglob
  archives=("${DIST_DIR}"/oauth2relay_"${RELEASE}"_*)
  shopt -u nullglob
  if [ ${#archives[@]} -eq 0 ] || [ ! -f "${DIST_DIR}/SHA256SUMS" ]; then
    echo "Error: no ${RELEASE} archives in ${DIST_DIR}; run: make release VERSION=${RELEASE}" >&2
    exit 1
  fi
  (cd "${DIST_DIR}" && sha256sum -c --quiet SHA256SUMS)
  for f in "${archives[@]}" "${DIST_DIR}/SHA256SUMS"; do
    case "$f" in
      *.tar.gz) type="application/gzip" ;;
      *.zip) type="application/zip" ;;
      *) type="text/plain; charset=utf-8" ;;
    esac
    aws s3 cp "$f" "s3://${BUCKET}/downloads/v${RELEASE}/$(basename "$f")" \
      --region "${AWS_REGION}" \
      --content-type "${type}" --no-guess-mime-type \
      --cache-control "public, max-age=31536000, immutable" \
      ${DRYRUN}
  done
fi

# Upload everything except index.html with the default caching, skipping
# editor/OS junk files. downloads/ is managed by --release and the Go module
# pages by the step below, never by sync.
aws s3 sync "${SOURCE_DIR}" "s3://${BUCKET}" \
  --region "${AWS_REGION}" \
  --exclude ".*" --exclude "*.swp" --exclude "*~" \
  --exclude "index.html" --exclude "downloads/*" \
  --exclude "oauth2relay" --exclude "oauth2relay/*" \
  ${DELETE} ${DRYRUN}

# Go module pages. "go get oauth2relay.com/oauth2relay/v2/..." requests
# https://oauth2relay.com/<path>?go-get=1 and reads the go-import meta tag,
# which names the Git repository. S3 ignores the query, so one page is
# stored under the key of every path the go command may ask for: the
# repository root, the module and each package. Browsers are redirected to
# the documentation. Missing keys would fall back to index.html, which has
# no go-import tag.
MODULE="$(cd "${SCRIPT_DIR}" && go list -m)"              # oauth2relay.com/oauth2relay/v2
HOST="${MODULE%%/*}"                                       # oauth2relay.com
REPO_ROOT="${MODULE%/v[0-9]*}"                             # oauth2relay.com/oauth2relay
GO_PAGE="$(mktemp)"
trap 'rm -f "${GO_PAGE}"' EXIT
cat >"${GO_PAGE}" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="go-import" content="${REPO_ROOT} git ${GO_IMPORT_REPO}">
<meta name="robots" content="noindex">
<meta http-equiv="refresh" content="0; url=https://${HOST}/docs.html">
<title>${MODULE}</title>
</head>
<body>
<p>Go module <code>${MODULE}</code>. See the <a href="https://${HOST}/docs.html">documentation</a>.</p>
</body>
</html>
HTML
go_paths=("${REPO_ROOT}" $(cd "${SCRIPT_DIR}" && go list -m && go list ./... | grep -v /internal/))
for p in "${go_paths[@]}"; do
  aws s3 cp "${GO_PAGE}" "s3://${BUCKET}/${p#"${HOST}"/}" \
    --region "${AWS_REGION}" \
    --content-type "text/html; charset=utf-8" --no-guess-mime-type \
    --cache-control "public, max-age=3600" \
    --only-show-errors ${DRYRUN}
done
echo "Published go-import pages for ${#go_paths[@]} paths under ${REPO_ROOT} -> ${GO_IMPORT_REPO}"

# index.html changes most often, so ask browsers to revalidate it every time.
aws s3 cp "${SOURCE_DIR}/index.html" "s3://${BUCKET}/index.html" \
  --region "${AWS_REGION}" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "no-cache" \
  ${DRYRUN}

if [ -n "${DRYRUN}" ]; then
  echo "Dry run: skipping CloudFront invalidation of ${DISTRIBUTION_ID}."
  exit 0
fi

echo "Invalidating CloudFront distribution ${DISTRIBUTION_ID}..."
INVALIDATION_ID=$(aws cloudfront create-invalidation \
  --distribution-id "${DISTRIBUTION_ID}" \
  --paths "/*" \
  --query Invalidation.Id --output text)
echo "Invalidation ${INVALIDATION_ID} created."

if [ -z "${WAIT}" ]; then
  echo "Not waiting. To check later: aws cloudfront wait invalidation-completed --distribution-id ${DISTRIBUTION_ID} --id ${INVALIDATION_ID}"
  exit 0
fi

echo "Waiting for the invalidation to complete (usually 1-5 minutes)..."
aws cloudfront wait invalidation-completed \
  --distribution-id "${DISTRIBUTION_ID}" \
  --id "${INVALIDATION_ID}"
echo "Invalidation ${INVALIDATION_ID} completed. The new site is live."
