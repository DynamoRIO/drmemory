# Contributing to Dr. Memory

We welcome contributions to Dr. Memory.  See our [list of project ideas for
contributors](http://drmemory.org/projects.html) and also [our list that
includes DynamoRIO
projects](https://github.com/DynamoRIO/drmemory/wiki/Projects).

If you would like to contribute code to Dr. Memory, you will need to first sign a
[Contributor License Agreement](https://developers.google.com/open-source/cla/individual).

Our wiki contains further information on policies, how to check out the
code, and how to add new code:

- [Contribution policies and suggestions](https://github.com/DynamoRIO/drmemory/wiki/Contributing)
- [Git workflow](https://github.com/DynamoRIO/drmemory/wiki/Workflow)
- [Code style guide](https://github.com/DynamoRIO/drmemory/wiki/Code-Style)
- [Code reviews](https://github.com/DynamoRIO/drmemory/wiki/Code-Reviews)

## Reporting issues

To report issues in Dr. Memory, please fill in the body of the issue with
this template:

```
What steps will reproduce the problem?
1.
2.
3.

What is the expected output? What do you see instead?


What version of the product are you using? On what operating system?


Does the problem go away when running in light mode (pass "-light" to Dr.
Memory)?  What about when running with the options "-leaks_only
-no_count_leaks -no_track_allocs"?

Does the problem go away when using the most recent build from
https://github.com/DynamoRIO/drmemory/wiki/Latest-Build?

Try the debug version of Dr. Memory and of its underlying engine DynamoRIO
by passing "-debug -dr_debug -pause_at_assert" to drmemory.exe. Are any
messages reported?

Please provide any additional information below.  Please also see the
"Narrowing Down the Source of the Problem" section
of https://github.com/DynamoRIO/drmemory/wiki/Debugging.
```

### Including code in issues

The text in an issue is interpreted as Markdown.  To include any kind of
raw output or code that contains Markdown symbols, place it between lines
that consist solely of three backtics:
<pre>
```
</pre>

### Attaching images or files to issues

Place the attachment on Google Drive or some other location and include a
link to it in the issue text.

## Filing feature requests

Before filing a feature request, check the documentation to ensure it is
not already provided.

Please provide the following information in an issue filed as a feature
request:

```
What is the goal of the new feature?

If there is a current method of accomplishing this goal, describe the
problems or shortcomings of that method and how the proposed feature would
improve the situation.
```
