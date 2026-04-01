#!/usr/bin/env bash

CWD="$PWD"

RELEASES_DIR="$1"
if [ -z "$RELEASES_DIR" ]; then
    echo "Usage: $0 <RELEASES_DIR>"
    exit 1
fi
if [ ! -d "$RELEASES_DIR" ]; then
    echo "Releases directory '$RELEASES_DIR' does not exist"
    exit 1
fi

cd "$RELEASES_DIR"
echo ""
echo "Releases dir:"
ls -lhrt

echo ""
echo "Searching for zipped releases..."
for DIR in * ; do
    if [ -d "$DIR" ]; then
        cd "$DIR"
        for FILE in * ; do
            if [ ! -d "$FILE" ]; then
                if [ "$FILE" = "release.zip" ]; then
                    echo "Found zipped release '$DIR'"
                    mv "$FILE" "../$DIR.zip"
                    rm -rf "../$DIR/"
                fi
            fi
        done
        cd ..
    fi
done

echo ""
echo "Releases dir:"
ls -lhrt

cd "$CWD"
