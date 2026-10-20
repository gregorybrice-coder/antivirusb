# antivirusb : sur la console principale, le menu de la station démarre directement.
# (Un terminal ouvert depuis le menu Administration définit AVB_SHELL et arrive ici normalement.)
if [ "$(tty)" = "/dev/tty1" ] && [ -z "$AVB_SHELL" ]; then
    setterm --blank 0 --powersave off 2>/dev/null
    /usr/local/bin/antivirusb
    logout
fi
[ -f ~/.bashrc ] && . ~/.bashrc
