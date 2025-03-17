## LoopRepair

LoopRepair improves iterative repair strategies by location-aware and trace-guided iterative Automated Vulnerability Repair (AVR).

## Install [VulnLoc+](https://github.com/nus-apr/CrashRepair) Dataset
Please go to [CrashRepair](https://github.com/nus-apr/CrashRepair) project to download the docker images. And the original VulnLoc dataset is provided by [VulnLoc](https://github.com/VulnLoc/VulnLoc).

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
___Step 1___: Download our looprepair project to `path/to/looprepair`.
___Step 2___: If you have installed this docker, use the following code to create the container.

```docker run -v path/to/looprepair/results:/results -v path/to/looprepair/logs:/logs -v path/to/looprepair/src:/looprepair -t crepair:aio```

___Step 3___: Use the following code to get into the container.

```docker exec -it crepair:aio bash``` 
___Step 4___: Install the Anaconda3 wegt the Anaconda3-2024.02-1-Linux-x86_64.sh by yourself and install Anaconda3. 

```./Anaconda3-2024.02-1-Linux-x86_64.sh```
___Step 5___: Add the Anaconda environment variable. Create a vitual environment.
```conda create -n looprepair python=3.9.11```

___Step 6___: pip install these packages that needed.

```cd /looprepair/crashrepair && pip install -r requirements.txt```
___Step 7___: Run repair. *Noting that cp the /data/ directory first `cp /data/ /data_bak/`, because the original program will be modified if you terminate.*

```python run.py```
