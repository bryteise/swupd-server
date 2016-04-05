swupd-server
-------

[![Build Status](https://travis-ci.org/bryteise/swupd-server.svg?branch=master)](https://travis-ci.org/bryteise/swupd-server)
[![Coverage Status](https://coveralls.io/repos/github/bryteise/swupd-server/badge.png?branch=master)](https://coveralls.io/github/bryteise/swupd-server?branch=master)

The swupd-server package provides a reference implementation of a software
update server-side component that generates update content consumable by a
software update client (swupd-client). Such content includes manifests that
describe incremental changes in the OS from build to build, binary deltas,
full copies of files (fullfiles) that were added/changed from a previous
build, and packs composed of binary deltas and/or fullfiles.
