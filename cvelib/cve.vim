" Vim syntax file for CVE entries
"
" SPDX-License-Identifier: MIT
"
" To use (use ~/.vim/syntax and ~/.vimrc for vim):
" $ mkdir -p ~/.config/nvim/syntax
" $ ln -s /path/to/sedg/cve.vim ~/.config/nvim/syntax/cve.vim
"
" Add to ~/.config/nvim/init.vim:
" autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set ft=cve
" autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9GN]* set syntax=cve
"
" Optionally add to ~/.config/nvim/init.vim to have syntax for CVE templates
" (assumes /path/to/your-cve-data/templates):
" autocmd BufNewFile,BufRead *cve*/templates/* set ft=cve
" autocmd BufNewFile,BufRead *cve*/templates/* set syntax=cve
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

syn match cveId contained "CVE-[0-9][0-9][0-9][0-9]-\([0-9]\{4,12\}\|NNN[0-9]\|NN[0-9][0-9]\|N[0-9]\{3,11\}\|GH[0-9]\+#[a-zA-Z0-9+._-]\+\)"
syn match cveDate contained "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveNotesValue contained /^\( @\?[a-zA-Z0-9._-]\+>.*\|  .\+\)$/
syn match cveStatus contained "\(needs\-triage\|needed\|deferred\|pending\|released\|ignored\|not\-affected\|DNE\)"
syn match cveStatusExtra contained " (.\+)"
syn match cvePriorityValue contained "\(negligible\|low\|medium\|high\|critical\)"
syn match cvePatchesValue contained /^ \(distro\|other\|upstream\|vendor\|break-fix\): .\+$/
syn match cveListURLs contained /^ \(cvs\|ftp\|git\|https\?\|sftp\|shttp\|svn\):\/\/.\+$/
syn match cveTagValue contained "\(apparmor\|fortify-source\|hardlink-restriction\|heap-protector\|limit-report\|pie\|stack-protector\|symlink-restriction\) *"

" this could use a subgroup for each of type of alert
syn match cveGHASValue contained /^ \(- type: \(dependabot\|secret-scanning\|code-scanning\)\|  \(dependency\|secret\|description\|detectedIn\): .\+\|  severity: \(low\|medium\|high\|critical\)\|  status: \(needs-triage\|needed\|released\|removed\|dismissed (\(started\|no-bandwidth\|tolerable\|inaccurate\|code-not-used\|auto\|revoked\|false-positive\|used-in-tests\|wont-fix\); [a-zA-Z0-9._-]\+)\)\|  \(advisory\|url\): \(https:\/\/.\+\|unavailable\)\)$/
syn match cveScanReportsValue contained /^ \(- type: oci\|  \(component\|detectedIn\|version\|fixedBy\): .\+\|  severity: \(negligible\|low\|medium\|high\|critical\|unknown\)\|  status: \(needs-triage\|needed\|released\|dismissed (\(tolerable\|code-not-used\); [a-zA-Z0-9._-]\+)\)\|  \(advisory\|url\): \(https:\/\/.\+\|unavailable\)\)$/

" Standard keys that don't have any extra data in the key name
syn match cveKey "^\%(Candidate\|OpenDate\|PublicDate\|CRD\|References\|Description\|GitHub-Advanced-Security\|Scan-Reports\|Notes\|Mitigation\|CVSS\|Bugs\|Discovered-by\|Assigned-to\): *"

" CloseDate[_<software>[/<modifier>]]: <date>
syn match cveCloseDateKey "^CloseDate\(_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?\)\?: *"

" Priority[_<software>[/<modifier>]]: <priority>
syn match cvePriorityKey "^Priority\(_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?\)\?: *"

" Patches_<software>:
syn match cvePatchesKey "^Patches_[a-zA-Z0-9][a-zA-Z0-9+._-]\+: *"

" Tags_<software>[/<modifier>]: <tag>
syn match cveTagKey "^Tags_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?: *"

" <product>[/<where>]_<software>[/<modifier>]:
syn match cveProductKey "^\%(upstream\|bzr\|cvs\|git\|hg\|svn\|appimage\|archive\|deb\|dmg\|exe\|flatpak\|oci\|rpm\|shell\|snap\|alpine\|android\|centos\|debian\|distroless\|flatcar\|ios\|opensuse\|osx\|rhel\|suse\|ubuntu\|windows\)\(/[a-z0-9+.-]\+\)\?_[a-zA-Z0-9][a-zA-Z0-9+._-]\+\(/[a-z0-9+.-]\+\)\?: *"


"
" Extra syntax checking
"
syn region cveStrictField start="^Candidate" end="$" contains=cveKey,cveId
syn region cveStrictField start="^\(OpenDate\|PublicDate\|CRD\)" end="$" contains=cveKey,cveDate
syn region cveStrictField start="^\(References\|Bugs\)" end=/^[^ ]/me=s-1 contains=cveKey,cveListURLs
syn region cveStrictField start="^Notes" end=/^[^ ]/me=s-1 contains=cveKey,cveNotesValue
syn region cveStrictField start="^GitHub-Advanced-Security" end=/^[^ ]/me=s-1 contains=cveKey,cveGHASValue
syn region cveStrictField start="^Scan-Reports" end=/^[^ ]/me=s-1 contains=cveKey,cveScanReportsValue

syn region cveStrictField start="^CloseDate" end="$" contains=cveCloseDateKey,cveDate oneline
syn region cveStrictField start="^Priority" end="$" contains=cvePriorityKey,cvePriorityValue oneline
syn region cveStrictField start="^Patches_" end=/^[^ ]/me=s-1 contains=cvePatchesKey,cvePatchesValue
syn region cveStrictField start="^Tags" end="$" contains=cveTagKey,cveTagValue oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveProductKey,cveStatus,cveStatusExtra oneline

" set the highlights
hi def link cveKey                 Keyword
hi def link cveCloseDateKey        Keyword
hi def link cvePriorityKey         Keyword
hi def link cvePatchesKey          Keyword
hi def link cveTagKey              Keyword
hi def link cveProductKey          Keyword
hi def link cveStrictField         Error
hi def link cveElse                Normal

" vim: ts=8 sw=2
