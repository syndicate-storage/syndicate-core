Test Layout
===========

You will need to fill in `testconf.py` with the appropriate paths to the following:
* the directories containing the built Python path, the built `syndicate` tool, and the built MS (from [syndicate-core](https://github.com/syndicate-storage/syndicate-core))
* the directory containing the built UG tools (from [syndicate-ug-tools](https://github.com/syndicate-storage/syndicate-ug-tools))
* the directory containing the built RG (from [syndicate-rg](https://github.com/syndicate-storage/syndicate-rg))
* the directory containing the built AG (from [syndicate-ag](https://github.com/syndicate-storage/syndicate-ag))

In practice, I just symlink all of the above into the current directory.

Tests can be run as-is.  They exit with status 0 if they worked.
