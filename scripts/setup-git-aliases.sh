#!/usr/bin/env bash

GIT=git
GITCONFIG="${GIT} config"

# General aliases that could be global
${GITCONFIG} alias.prepush 'log --graph --stat origin/master..'

# Alias to push the current topic branch to Gerrit
${GITCONFIG} alias.gerrit-push "!bash scripts/git-gerrit-push"
${GITCONFIG} alias.gerrit-merge "!bash scripts/git-gerrit-merge"
