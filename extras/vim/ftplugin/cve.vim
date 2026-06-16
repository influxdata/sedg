if exists('b:did_ftplugin') | finish | endif
let b:did_ftplugin = 1

" retain default autoindent behavior, but also allow reflowing 'gqgq' with
" lists properly
setlocal autoindent
setlocal formatoptions+=n
setlocal comments=                    " let formatlistpat own all bullet reflow
setlocal formatlistpat&
let &l:formatlistpat .= '\|^\s*[-*+]\s\+'
