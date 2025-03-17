## LoopRepair

LoopRepair improves iterative repair strategies by location-aware and trace-guided iterative Automated Vulnerability Repair (AVR).

## Install VulnLoc+ Dataset

```
git clone https://github.com/nus-apr/CrashRepair.git
cd CrashRepair
./scripts/install
```

It is worth noting that some projects should be executed with special version (project version):
```
spdlog v1.12.0
z3 z3-4.13.4
pegtl main
```
please git checkout to the special version of these three project. Otherwise, this dataset project will error.

Futhermore, the `crepair:aio` image is 23.8GB in size, so please check that the installed image is correct.

## Run LoopRepair
- Step 1: Download our looprepair project to `path/to/looprepair`.
- Step 2: If you have installed this docker, use `docker run -v path/to/looprepair/results:/results -v path/to/looprepair/logs:/logs -v path/to/looprepair/src:/looprepair -t crepair:aio` to create the container 
- Step 3: `docker exec -it crepair:aio bash` to get into the container.
- Step 4: Install the Anaconda3 `wegt the Anaconda3-2024.02-1-Linux-x86_64.sh by yourself` and `./Anaconda3-2024.02-1-Linux-x86_64.sh`.
- Step 5: Add the Anaconda environment variable. Create a vitual environment `conda create -n looprepair python=3.9.11`
- Step 6: `cd /looprepair/crashrepair` and `pip install -r requirements.txt` to install packages.
- Step 7: `python run.py` to run repair. *Noting that cp the /data/ directory first `cp /data/ /data_bak/`, because the original program will be modified if you terminate.*
