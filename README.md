
# MEMORY BASELINER

## Description
This script focuses on analysis of memory images taken of computers running
Microsoft Windows. It implements the following two use cases:
* "compare" two memory images (e.g. golden image to suspicious computer or memory snapshots during dynamic malware analysis)
* perform frequency of occurrence / data stacking analysis on multiple memory
images

Analysis aspects
* process & DLL
* service
* driver

Analysis types
* comparison (default)
* data stacking / frequency of occurrence

## Background
It's common in many enterprise environments, that windows based computers are
provisioned using so-called "golden images" or installation scripts. This
practice enables administrators to deploy servers and clients easier and faster
and helps implementing / enforcing the configuration standard.

This practice also provides forensic investigators and incident responders with
an advantage. Because of the way the computers are provisioned most of them show
many similarities. Most of the standard services, drivers and processes are
similar, therefore it's possible to identify outliers by "comparing" the
computers (disk and memory) to each other. This capability can speed up incident
response and forensic analysis.

In order for the script to be more effective the images should be taken of
computers running the same version of Microsoft Windows. This enables the
analyst to use further comparison options to enhance accuracy and thereby
improve detection.

## Requirements
This script was written in python3
This script uses volatility version 3 as a library and must be copied into the
folder where vol.py resides.

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
format. This can also be saved to a file (the "-o" option is doing that for you)

The output will include the following columns
Process & DLL analysis:
PID: process ID
PPID (PARENT NAME): parent process ID and the name of the parent process
PROCESS NAME: name of the process
PROCESS IMPHASH: import hash value of the process
COMMAND LINE: command line of the process
DLL NAME: name of the loaded DLL
DLL PATH: path to the loaded DLL
DLL IMPHASH: import hash value of the loaded DLL
PROCESS STATUS: KNOWN or UNKNOWN based if the process has been found in the baseline image
DLL STATUS: KNOWN or UNKNOWN based on if the DLL has been found in the baseline image
BASELINE FoO: Frequency of Occurrence in the baseline image
IMAGE FoO: Frequency of Occurrence in the baseline image

Service analysis:
STATUS: KNOWN or UNKNOWN based on if the service has been found in the baseline image
NAME: name of the service
DISPLAY: display name of the service
STATE: state of the service (e.g.: SERVICE_STOPPED)
TYPE: type of the service (e.g.: SERVICE_WIN32_SHARE_PROCESS)
START: start type of the service (e.g.: SERVICE_DEMAND_START)
OWNER: owner of the process started by the service
BINARY: the executable / command that is executed when the service starts

Driver analysis:
STATUS: KNOWN or UNKNOWN based on if the driver has been found in the baseline image
NAME: name of the driver
SIZE: size of the driver in hex
IMPHASH: import hash value of the driver
PATH: path to the driver on disk

Process stacking:
FoO: Frequency of Occurrence
IMPHASH: process import hash value
IMAGES: list of images the driver was found in
PROCESS NAME: name of the process
PROCESS CMD LINE: command line of the process

DLL stacking:
FoO: Frequency of Occurrence
IMPHASH: DLL import hash value
IMAGES: list of images the driver was found in
DLL NAME: name of the DLL
DLL PATH: path to the DLL on disk

Service stacking:
FoO: Frequency of Occurrence
IMAGES: list of images the driver was found in
SERVICE NAME: name of the service
SERVICE DISPLAY: display name of the service
SERVICE TYPE: type of the service
SERVICE START: start type of the service
SERVICE STATE: state of the service
SERVICE PROCESS OWNER: owner of the process started by the service
SERVICE BINARY: executable of command line that is executed upon service start

Driver stacking:
FoO: Frequency of Occurrence
IMAGES: list of images the driver was found in
DRIVER NAME: driver name
DRIVER IMPHASH: driver import hash value
DRIVER IMAGE SIZE: driver image size in hex
DRIVER PATH: path to the driver on disk




## Usage
```
usage: baseline.py [-h] [-b BASELINE] [-i IMAGE] [-d IMAGEDIR] [-o OUTPUT] [-proc] [-drv] [-svc] [-procstack] [-dllstack] [-drvstack] [-svcstack] [--imphash] [--owner] [--cmdline] [--state] [--showknown] [--savebaseline]
                   [--loadbaseline] [--jsonbaseline JSONBASELINE]

optional arguments:
  -h, --help            show this help message and exit
  -b BASELINE, --baseline BASELINE
                        The baseline image
  -i IMAGE, --image IMAGE
                        The image to analyze
  -d IMAGEDIR, --imagedir IMAGEDIR
                        The directory with images to analyze. Used for stacking
  -o OUTPUT, --output OUTPUT
                        The output file where the results are to be saved
  -proc                 Process analysis & DLL analysis
  -drv                  Driver analysis
  -svc                  Service analysis
  -procstack            Perform process stacking on the image(s)
  -dllstack             Perform DLL stacking on the image(s)
  -drvstack             Perform driver stacking on the image(s)
  -svcstack             Perform service stacking on the image(s)
  --imphash             Also compare import hashes
  --owner               Also compare process owners
  --cmdline             Also compare process command lines
  --state               Also compare service states
  --showknown           Include known items in the output (prcesses, dlls, driver, services)
  --savebaseline        Save the baseline results of the analysis to a JSON file
  --loadbaseline        Load the baseline results of the analysis from a JSON file
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
python3 baseline.py -dllstack --imphash -d <directory containing the images>
```
Process stacking
```bash
python3 baseline.py -procstack -d <directory containing the images>
```
