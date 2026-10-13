# Private crossrepo paths

Windows Python/Git and Linux Python/Git resolved the original ~/hubdemo/calc dependency to the same disposable NTFS checkout. Windows used a directory junction under a private process USERPROFILE; Linux used a symlink under a private HOME. Original setup/report source bytes stayed unchanged. Both observed the same marker and Git HEAD and imported the baseline report.

Canonical Windows client profile paths were passed only as strings. This does not prove actual clients honor those overrides or qualify authentication, shared-profile preservation or original provider orchestration. No real user home, profile or config was changed. The initial PowerShell argument-binding failure remains recorded.
