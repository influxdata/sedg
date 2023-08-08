" Vim syntax file for CVE entries
"
" SPDX-License-Identifier: MIT

" Only load if no other indent file is loaded
if exists('b:did_indent') | finish | endif
let b:did_indent = 1

setlocal indentexpr=GetCVEIndent()

" Only define the function once
if exists("*GetCVEIndent") | finish | endif

function! GetCVEIndent()
  " Get number of last non-blank line
  let prevlnum = prevnonblank(v:lnum - 1)

  " if previous is a multiline Field, then set indent to 1
  if getline(prevlnum) =~ '^\(References\|Description\|GitHub-Advanced-Security\|Scan-Reports\|Notes\|Mitigation\|Bugs\|Patches_.\+\): *$'
    return 1
  elseif getline(prevlnum) =~ '^ @\?[a-zA-Z0-9._-]\+>.*'
    " if it looks like we are in a ' foo>...' 'Notes' field entry,
    " look back and see if actually within Notes. If so, indent 2
    let lnum = prevlnum
    while lnum > 2
      let lnum = lnum - 1
      if getline(lnum) =~ '^[^ ]'  " find the last Field line
        if getline(lnum) =~ '^Notes: *$'
          return 2
        endif
        break
      endif
    endwhile
  endif

  return -1  " if none of the above, don't override current indent
endfunction
