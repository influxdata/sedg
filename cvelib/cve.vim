" Vim syntax file for CVE entries
"
" Copyright (c) 2021-2023 InfluxData
"
" Permission is hereby granted, free of charge, to any
" person obtaining a copy of this software and associated
" documentation files (the "Software"), to deal in the
" Software without restriction, including without
" limitation the rights to use, copy, modify, merge,
" publish, distribute, sublicense, and/or sell copies of
" the Software, and to permit persons to whom the Software
" is furnished to do so, subject to the following
" conditions:
"
" The above copyright notice and this permission notice
" shall be included in all copies or substantial portions
" of the Software.
"
" THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
" ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
" TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
" PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
" SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
" CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
" OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
" IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
" DEALINGS IN THE SOFTWARE.
"
" To use:
" $ mkdir -p ~/.vim/syntax
" $ ln -s /path/to/cvelib/cve.vim ~/.vim/syntax/cve.vim
" Add to ~/.vimrc:
" autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set syntax=cve
"
" Reload in an open file with:
" :set syntax=off
" :set syntax=cve
"
" Start clean:
" $ vim -u DEFAULTS -U NONE -i NONE -c 'syntax on' -c set syntax=cve' ...
" :set syntax=cve

if exists("b:current_syntax")
    finish
endif
let b:current_syntax = "cve"

" Should match case except for the keys of each field
syn case match

" Everything that is not explicitly matched by the rules below
syn match cveElse "^.*$"

syn match cveRelease "\(git\|snap\|oci\|upstream\|alpine\|debian\|suse\|ubuntu\)\(/[a-z0-9+.-]\+\)\?"
syn match cveSrcPkg contained "[a-zA-Z0-9][a-zA-Z0-9+._-]\+"
syn match cveId contained "CVE-[0-9][0-9][0-9][0-9]-\([0-9]\{4,12\}\|NNN[0-9]\|NN[0-9][0-9]\|N[0-9]\{3,11\}\|GH[0-9]\+#[a-zA-Z0-9+._-]\+\)"
syn match cveDate contained "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveStatus contained "\(needs\-triage\|needed\|deferred\|pending\|released\|ignored\|not\-affected\|DNE\)"
syn match cveStatusExtra contained " (.\+)"

" Standard keys
syn match cveKey "^\%(Candidate\|OpenDate\|PublicDate\|CRD\|References\|Description\|GitHub-Advanced-Security\|Notes\|Mitigation\|CVSS\|Bugs\|Discovered-by\|Assigned-to\|Patches_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\): *"

" TODO: reuse the above definitions here
" Release/status key
" <release>_<software>[/<modifier>]: <status>
syn match cveKeyRelease "^\%(git\|snap\|oci\|upstream\|alpine\|debian\|suse\|ubuntu\)\(/[a-z0-9+.-]\+\)\?_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?: *"
"
" TODO: reuse the above definitions here
" CloseDates key
" CloseDate[_<software>[/<modifier>]]: <date>
syn match cveCloseDateValue contained "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveCloseDateKey "^CloseDate\(_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?\)\?: *"

" TODO: reuse the above definitions here
" Priorities key
" Priority[_<software>[/<modifier>]]: <priority>
syn match cvePriorityValue contained "\(negligible\|low\|medium\|high\|critical\)"
syn match cvePriorityKey "^Priority\(_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?\)\?: *"

" TODO: reuse the above definitions here
" Tags key
" Tags_<software>[/<modifier>]: <tag>
syn match cveTagValue contained "\(apparmor\|fortify-source\|hardlink-restriction\|heap-protector\|limit-report\|pie\|stack-protector\|symlink-restriction\) *"
syn match cveTagKey "^Tags_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?: *"

" Fields where we do strict syntax checking
syn region cveStrictField start="^CloseDate" end="$" contains=cveCloseDateKey,cveCloseDateValue oneline
syn region cveStrictField start="^Priority" end="$" contains=cvePriorityKey,cvePriorityValue oneline
syn region cveStrictField start="^Tags" end="$" contains=cveTagKey,cveTagValue oneline
syn region cveStrictField start="^Candidate" end="$" contains=cveKey,cveId
syn region cveStrictField start="^\(OpenDate\|PublicDate\|CRD\)" end="$" contains=cveKey,cveDate
syn region cveStrictField start="^Patches_" end=":$" contains=cveKey,cveSrcPkg oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveKeyRelease,cveStatus,cveStatusExtra oneline

" set the highlights
hi def link cveKey                 Keyword
hi def link cveCloseDateKey        Keyword
hi def link cvePriorityKey         Keyword
hi def link cveTagKey              Keyword
hi def link cveKeyRelease          Keyword
hi def link cveElse                Normal
hi def link cveStrictField         Error

" vim: ts=8 sw=2
