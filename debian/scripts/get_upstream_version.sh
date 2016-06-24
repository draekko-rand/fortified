#!/bin/sh

# determine upstream version from the entry in debian/changelog
# 
# thanks Josip Rodin, it  looks ugly but doesn't have much fork()'s
# address comments to him  - <joy@debian.org> :)

perl -pe 's/^.*\((?:[^:]+:)?([^-]+)(?:-\S+)?\).*$/$1/; last if ($. > 1)' \
	< debian/changelog

