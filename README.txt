Feuerfuchs
----------

The patch should apply cleanly to the latest release branch of firefox:

    git clone https://github.com/mozilla/gecko-dev.git feuerfuchs
    cd feuerfuchs
    git checkout origin/release
    patch -p1 < ../feuerfuchs.patch
    ./mach build

The dockerimage/ directory contains everything to reproduce the container setup that is used by the challenge server:

    1. ./docker_build.sh

    2. ./docker_run.sh

    3. (in a separate shell) ./launch_firefox.sh $URL

    4. (optional, also in a separete shell) ./take_screenshot.sh && open screenshot.png
