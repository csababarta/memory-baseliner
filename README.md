
# MEMORY BASELINER

## Description
This script focuses on analysis of memory images taken of computers running
Microsoft Windows. It implements the following two use cases:
* "compare" two memory images (e.g. golden image to suspicious computer or memory snapshots during dynamic malware analysis)
* perform frequency of occurrence / data stacking analysis on multiple memory
images

Analysis aspects
* process
* DLL
* service
* driver

Analysis types
* comparison (default)
* data stacking / frequency of occurrence

## Background
It's common in many enterprise environments, that windows based computers are
provisioned using so-called "golden images" or installation scripts. This
practice enables administrators to easier and faster to deploy servers and
clients and helps implementing / enforcing the configuration standard.

This practice also provides forensic investigators and incident responders with
an advantage. Because of the way the computers are provisioned most of them show
many similarities. Most of the standard services, drivers and processes are
similar, therefore it's possible to identify outliers by "comparing" the
computers to each other. This capability can speed up incident response and
forensic analysis.

In order to be the most effective the images should be taken of the same version
of Microsoft Windows. This enables the analyst to use further comparison options
to enhance accuracy and thereby improve detection.

## Requirements
This script was written in python3
This script uses volatility version 3 as a library

## Installation / setup
Copy the following files into the directory where vol.py (version 3) resides.
* baseline.py
* baseline_objects.py

## Comparison options
By default the the script will only compare the following properties:

### Process analysis (also performs DLL analysis)
* process name (EPROCESS)
* process path (PEB)
* process parent
* DLL name
* DLL path
* DLL image size

### DLL analysis (in case of data stacking)
* DLL name
* DLL path
* DLL image size

### Service analysis
* service name
* service display name
* service type
* service start
* service binary

### Driver analysis
* driver name
* driver path
* driver image size

By enabling the following command line switches it is possible to perform
additional comparisons to improve detection accuracy. Note: This will result in more unknown processes/DLLs/drivers/services in case the windows versions in the images are different.

* --imphash: will also compare the import hashes in case of process, DLL and driver analysis
* --owner: will also compare the process owner in case of process and service analysis
* --cmdline: will also compare the command line in case of process analysis
* --state: will also compare service states

## Saving baseline results into JSON files
This option will save the results of the analysis into a JSON file that can be
loaded later to speed up the analysis process. This is useful if you would like
to compare multiple images to the same baseline in multiple runs.

## Output
The script will output its results to the standard output in tab separated
format. This can redirected to a file.

## Usage
```
usage: baseline.py [-h] [-b BASELINE] [-i IMAGE] [-proc] [-drv] [-dll] [-svc] [--stack] [--imphash] [--owner] [--cmdline] [--state] [--showknown] [--savebaseline] [--loadbaseline]
                   [--jsonbaseline JSONBASELINE]

optional arguments:
  -h, --help            show this help message and exit
  -b BASELINE, --baseline BASELINE
                        The baseline image
  -i IMAGE, --image IMAGE
                        The image(s) to analyze
  -proc                 Process analysis
  -drv                  Driver analysis
  -dll                  DLL analysis
  -svc                  Service analysis
  --stack               Perform stacking on the image(s)
  --imphash             Also compare import hashes
  --owner               Also compare process owners
  --cmdline             Also compare process commandlines
  --state               Also compare service states
  --showknown           Include known items in the output (prcesses, dlls, driver, services)
  --savebaseline        Save the baseline results to a JSON file
  --loadbaseline        Load the baseline results from a JSON file
  --jsonbaseline JSONBASELINE
                        The JSON file where the baseline results are located
```
## Usage examples
Comparing processes in 2 images also showing known items /items that are the
  the same in the 2 images/
```bash
python3 baseline.py -proc --showknown -b <baseline image> -i <image to analyze>
```
Comparing processes in 2 images and saving the baseline into a JSON file
```bash
python3 baseline.py -proc --savebaseline --jsonbaseline <JSON baseline file> -b <baseline image> -i <image to analyze>
```
Comparing processes in 2 images and loading the baseline from a JSON file. Note:
  the baseline image is not needed as the results has already been saved
```bash
python3 baseline.py -proc --loadbaseline --jsonbaseline <JSON baseline file> -i <image to analyze>
```
Comparing services in 2 images and also compare service state
```bash
python3 baseline.py -svc --state -b <baseline image> -i <image to analyze>
```
Comparing drivers in 2 images
```bash
python3 baseline.py -drv -b <baseline image> -i <image to analyze>
```
DLL stacking comparing import hashes
```bash
python3 baseline.py -dll --stack --imphash -i <directory containing the images>
```
Process stacking
```bash
python3 baseline.py -proc --stack -i <directory containing the images>
```
