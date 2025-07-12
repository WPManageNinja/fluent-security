#!/bin/bash

# Usage: ./build.sh --node-build --loco

# Function to handle copying
copy_items() {
  local source_dir="$1"
  local destination_dir="$2"
  shift 2
  local copy_list=("$@")

  # Delete existing files in the destination directory
  rm -rf "$destination_dir" && mkdir -p "$destination_dir"

  # Copy selected folders and files
  for item in "${copy_list[@]}"; do
    local source_path="$source_dir/$item"
    local destination_path="$destination_dir/$item"

    if [ -e "$source_path" ]; then
      cp -r "$source_path" "$destination_path"
      echo "Copied: $item"
    else
      echo "Warning: $item does not exist in the source directory."
    fi
  done

  echo -e "\nCopy completed."
}

# Function to handle compression
compress_items() {
  local destination_dir="$1"

  # Compress the copied content
  local dest_dir_basename
  dest_dir_basename=$(basename "$destination_dir")
  (cd "$(dirname "$destination_dir")" && zip -rq "${dest_dir_basename}.zip" "$dest_dir_basename" -x "*.DS_Store")

  # Check for errors
  if [ $? -ne 0 ]; then
    echo "Error occurred while compressing."
    exit 1
  fi

  echo -e "\nCompressing Completed. builds/${dest_dir_basename}.zip is ready. Check the builds directory. Thanks!\n"
}

# Parse command-line arguments
nodeBuild=true

for arg in "$@"; do
  case "$arg" in
    "--node-build") nodeBuild=true ;;
  esac
done

# Execute build steps if required
if "$nodeBuild"; then
  echo -e "\nBuilding Main App\n"
  npx mix --production
  echo -e "\nBuild Completed for Main App\n"
fi


withLoco=false
for arg in "$@"; do
  case "$arg" in
    "--loco")
      withLoco=true
      ;;
  esac
done

if "$withLoco"; then
  node i18n.node.js
  echo -e "\nExtracting Loco Translations\n"
  # shellcheck disable=SC2164
  wp loco extract fluent-security
  echo -e "\Syncing Loco Translations\n"
  wp loco sync fluent-security
    # shellcheck disable=SC2164
  echo -e "\nLoco Translations synced\n"
fi

# Copy Fluent Boards
copy_items "." "builds/fluent-security" "app" "dist" "language" "fluent-security.php" "index.php" "readme.txt"

# Compress Fluent Boards
compress_items "builds/fluent-security"

exit 0
