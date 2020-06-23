---
name: Bug report
about: Create a report about a specific problem to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

If you just have a question, please use the users list https://groups.google.com/forum/#!forum/DrMemory-Users instead of this issue tracker, as it will reach a wider audience of people who might have an answer, and it will reach other users who may find the information beneficial. The issue tracker is for specific detailed bugs. If you are not sure it's a bug, please start by asking on the users list.  If you have already asked on the users list and the consensus was to file a new issue, please include the URL to the discussion thread here.

**To Reproduce**
Steps to reproduce the behavior:
1. Pointer to a minimized application (ideally the source code for it and instructions on which toolchain it was built with).
2. Precise command line for running the application.
3. Exact output or incorrect behavior.

Please also answer these questions drawn from  https://github.com/DynamoRIO/drmemory/wiki/Debugging#narrowing-down-the-source-of-the-problem :
 - Does the problem go away when running in light mode (pass `-light` to Dr. Memory)?
 - Does the problem go away when running with the options `-leaks_only -no_count_leaks -no_track_allocs`?
 - Does the problem go away when running under plain DynamoRIO?  Do this by running `dynamorio/bin32/drrun -- <application and args>` or `dynamorio/bin64/drrun -- <application and args>` depending on the bitwidth of your applicaiton.  (Ignore warnings about "incomplete installation".)
 - What happens with the debug version of Dr. Memory and of its underlying engine DynamoRIO?  Try this by passing `-debug -dr_debug -pause_at_assert`.  Are any messages reported?

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots or Pasted Text**
If applicable, add screenshots to help explain your problem.  For text, please cut and paste the text here, delimited by lines consisting of three backtics to render it verbatim, like this:
<pre>
```
paste output here
```
</pre>

**Versions**
 - What version of Dr. Memory are you using?
 - Does the latest build from
https://github.com/DynamoRIO/drmemory/wiki/Latest-Build solve the problem?
- What operating system version are you running on? ("Windows 10" is *not* sufficient: give the release number.)
- Is your application 32-bit or 64-bit?

**Additional context**
Add any other context about the problem here.
