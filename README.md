## LoopRepair

LoopRepair improves iterative repair strategies by location-aware and trace-guided iterative Automated Vulnerability Repair (AVR).

## Install VulnLoc+ Dataset
Please go to [CrashRepair](https://github.com/nus-apr/CrashRepair) project to download the docker images. And the original VulnLoc dataset is provided by [VulnLoc](https://github.com/VulnLoc/VulnLoc).

```
git clone https://github.com/nus-apr/CrashRepair.git
cd CrashRepair
./scripts/install
```

It is worth noting that some projects should be executed with special version (project version):
```
spdlog==v1.12.0
z3==z3-4.13.4
pegtl==main
```
please git checkout to the special version of these three project. Otherwise, this dataset project will error.

Futhermore, the `crepair:aio` image is 23.8GB in size, so please check that the installed image is correct.

## Run LoopRepair
___Step 1___: Download our looprepair project to `path/to/looprepair`.

___Step 2___: If you have installed this docker image, use the following code to create the container.

```
docker run --name LoopRepair -v path/to/looprepair/results:/results -v path/to/looprepair/logs:/logs -v path/to/looprepair/src:/looprepair -t crepair:aio
```

___Step 3___: Use the following code to get into the container.

```
docker exec -it crepair:aio bash
``` 

___Step 4___: Install the Anaconda3. wegt the Anaconda3-2024.02-1-Linux-x86_64.sh by yourself and install Anaconda3. 

1. _Download Anaconda3._
    ```
    wget https://mirrors.tuna.tsinghua.edu.cn/anaconda/archive/Anaconda3-2024.02-1-Linux-x86_64.sh
    ```
2. _Install Anaconda3._
    ```
    ./Anaconda3-2024.02-1-Linux-x86_64.sh
    ```
3. _Add the Anaconda environment variable._
    ```
    vim ~/.bashrc
    ```
4. _Add these two lines into the ~/.bashrc file._
    ```
    export PATH="~/anaconda3/bin":$PATH
    source ~/anaconda3/bin/activate
    ```
5. _update ~/.bashrc file._
    ```
    source ~/.bashrc
    ```
5. _Check conda._
    ```
    conda -V
    ```

___Step 5___: Create a vitual environment.

```
conda create -n looprepair python=3.9.11
```

___Step 6___: pip install these packages that needed.

```
cd /looprepair/crashrepair && pip install -r requirements.txt
```

___Step 7___: Add OpenAI API key in `LLMRepair.py`.
```
openai.api_key = ""
openai.base_url = ''
```

___Step 8___: Run repair. *Noting that `copy` the `/data/` directory first using `cp /data/ /data_bak/`, because the original program will be modified if you terminate.*
1. _Noting that `copy` the `/data/` directory first._
    ```
    cp /data/ /data_bak/
    ```
2. _Run looprepair._
    ```
    python run.py
    ```
3. _After every time you run or terminate the run.py, remove `/data/` dataset and replace it using `/data_bak`. This step aim to keep the program the same as original program._
    ```
    rm -rf /data/ 
    cp /data_bak/ /data/
    ```
