" Vim syntax file for CVE entries
" Latest Revision: Jul 1 2022
"
" To use:
" $ mkdir -p ~/.vim/syntax
" $ ln -s /path/to/cvelib/cve.vim ~/.vim/syntax/cve.vim
" Add to ~/.vimrc:
" autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set syntax=cve
" autocmd BufNewFile,BufRead 00boilerplate.* set syntax=cve
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

syn match cveRelease "\(git\|snap\|oci\|upstream\|ubuntu\|debian\|suse\)\(/[a-z0-9+.-]\+\)\?"
syn match cveSrcPkg contained "[a-zA-Z0-9][a-zA-Z0-9+._-]\+"
syn match cveId contained "CVE-[0-9][0-9][0-9][0-9]-\([0-9N]\{4,}\|GH[0-9]\+#[a-zA-Z0-9+.-]\+\)"
syn match cveDate contained "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveStatus contained "\(needs\-triage\|needed\|deferred\|pending\|released\|ignored\|not\-affected\|DNE\)"
syn match cveStatusExtra contained " (.\+)"

" Standard keys
syn match cveKey "^\%(Candidate\|OpenDate\|PublicDate\|PublicDateAtUSN\|CRD\|References\|Description\|GitHub-Advanced-Security\|Notes\|Mitigation\|CVSS\|Bugs\|Discovered-by\|Assigned-to\|Patches_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\): *"

" TODO: reuse the above definitions here
" Release/status key
" <release>_<srcpkg>: <status>
syn match cveKeyRelease "^\%(git\|snap\|oci\|upstream\|ubuntu\|debian\|suse\)\(/[a-z0-9+.-]\+\)\?_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?: *"

" TODO: reuse the above definitions here
" Priorities key
" Priority[_<srcpkg>[_<release>]]: <priority>
syn match cvePriorityValue contained "\(negligible\|low\|medium\|high\|critical\)"
syn match cvePriorityKey "^Priority\(_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(_\(upstream\|snap\)\)\?\)\?: *"

" TODO: reuse the above definitions here
" Tags key
" Tags_<srcpkg>[_<release>]: <tag>
syn match cveTagValue contained "\(apparmor\|fortify-source\|hardlink-restriction\|heap-protector\|pie\|stack-protector\|symlink-restriction\) *"
syn match cveTagKey "^Tags_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(_\(upstream\|snap\)\)\?: *"

" Fields where we do strict syntax checking
syn region cveStrictField start="^Priority" end="$" contains=cvePriorityKey,cvePriorityValue oneline
syn region cveStrictField start="^Tags" end="$" contains=cveTagKey,cveTagValue oneline
syn region cveStrictField start="^Candidate" end="$" contains=cveKey,cveId
syn region cveStrictField start="^\(OpenDate\|PublicDate\|PublicDateAtUSN\|CRD\)" end="$" contains=cveKey,cveDate
syn region cveStrictField start="^Patches_" end=":$" contains=cveKey,cveSrcPkg oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveKeyRelease,cveStatus,cveStatusExtra oneline

" set the highlights
hi def link cveKey                 Keyword
hi def link cvePriorityKey         Keyword
hi def link cveTagKey              Keyword
hi def link cveKeyRelease          Keyword
hi def link cveElse                Normal
hi def link cveStrictField         Error

" vim: ts=8 sw=2
