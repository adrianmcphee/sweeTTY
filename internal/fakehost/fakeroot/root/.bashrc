# ~/.bashrc: executed by bash(1) for non-login shells.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HISTSIZE=2000
export HISTFILESIZE=4000
export HISTCONTROL=ignoreboth

alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'

PS1='\[\e[0;31m\]\u@\h\[\e[0m\]:\[\e[0;34m\]\w\[\e[0m\]\$ '
