# MEMORY BASELINE
#
# Authors:  Csaba Barta
# Contact:  csaba.barta@gmail.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import argparse
import binascii
import csv
import io
import json
import logging
import os
import sys

from urllib import request
import uuid

from baseline_objects import BaselineDll, BaselineProcess, BaselineProcessList, BaselineDriver, BaselineDriverList, BaselineServiceList

import pefile

from volatility3 import framework, plugins
from volatility3.cli import PrintedProgress

def output_to_csv(file_handle: object,
                  headers: list,
                  records: list):
    csv_output = csv.writer(file_handle,
                            delimiter = "|",
                            quotechar = '"',
                            quoting = csv.QUOTE_ALL)
    # write headers
    csv_output.writerow(headers)
    # write records
    for r in records:
        csv_output.writerow(r)

def compare_processes(baseline: list,
                      image_to_check: list,
                      compare_imphash: bool,
                      compare_owner: bool,
                      compare_cmdline: bool,
                      show_known: bool,
                      output_handle: object):

    # collect DLL statistics
    baseline_dll_statistics = baseline.collect_dll_statistics(compare_imphash)
    image_dlls_statistics = image_to_check.collect_dll_statistics(compare_imphash)

    # check processes
    headers = ['PID',
               'PPID (PARENT NAME)',
               'PROCESS NAME',
               'PROCESS IMPHASH',
               'COMMAND LINE',
               'DLL NAME',
               'DLL PATH',
               'DLL IMPHASH',
               'PROCESS STATUS',
               'DLL STATUS',
               'BASELINE FoO',
               'IMAGE FoO']

    records = []
    for p in image_to_check.processes:
        # identify known processes

        baseline_process = None
        for bp in baseline.processes:
            if p.is_same_as(process = bp,
                            compare_imphash = compare_imphash,
                            compare_owner = compare_owner,
                            compare_cmdline = compare_cmdline):
                baseline_process = bp
                break

        if baseline_process == None:
            # unknown process

            # check DLLs
            for dll in p.dlls:
                # identify uknown DLLs
                known = False
                for d in baseline_dll_statistics:
                    if d['dll'].is_same_as(dll = dll,
                                           compare_imphash = compare_imphash):
                        # known DLL
                        known = True

                        # only continue if known DLLs should be included
                        if not show_known:
                            break

                        image_foo = -1
                        for image_dll_entry in image_dlls_statistics:
                            if dll.is_same_as(image_dll_entry['dll'], compare_imphash):
                                image_foo = image_dll_entry['frequency_of_occurence']

                        records.append([str(p.pid),
                                        "%d (%s)" % (p.ppid,
                                                     p.parent.process_name if p.parent != None else 'n/a'),
                                        p.process_name,
                                        p.process_imphash,
                                        p.process_cmd_line if p.process_cmd_line != '' else 'n/a',
                                        dll.dll_name,
                                        dll.dll_path,
                                        dll.dll_imphash,
                                        'UNKNOWN',  # process status
                                        'KNOWN',   # DLL status
                                        str(d['frequency_of_occurence']),  # Baseline FOO
                                        str(image_foo)])  # Image FOO
                        break
                if not known:
                    # unknown DLL
                    image_foo = -1
                    for image_dll_entry in image_dlls_statistics:
                        if dll.is_same_as(image_dll_entry['dll'], compare_imphash):
                            image_foo = image_dll_entry['frequency_of_occurence']
                    records.append([str(p.pid),
                                    "%d (%s)" % (p.ppid,
                                                 p.parent.process_name if p.parent != None else 'n/a'),
                                    p.process_name,
                                    p.process_imphash,
                                    p.process_cmd_line if p.process_cmd_line != '' else 'n/a',
                                    dll.dll_name,
                                    dll.dll_path,
                                    dll.dll_imphash,
                                    'UNKNOWN',  # process status
                                    'UNKNOWN',  # DLL status
                                    str(0), # Baseline FOO
                                    str(image_foo)]) # Image FOO
        else:
            # known process

            # only continue if known processes should be included
            if not show_known:
                continue

            # check DLLs
            for dll in p.dlls:
                # identify uknown DLLs
                baseline_dll_entry = None
                for d in baseline_dll_statistics:
                    if d['dll'].is_same_as(dll = dll,
                                           compare_imphash = compare_imphash):
                        baseline_dll_entry = d
                        break
                if baseline_dll_entry == None:
                    # unknown DLL
                    image_foo = -1
                    for image_dll_entry in image_dlls_statistics:
                        if dll.is_same_as(image_dll_entry['dll'], compare_imphash):
                            image_foo = image_dll_entry['frequency_of_occurence']
                    records.append([str(p.pid),
                                    "%d (%s)" % (p.ppid,
                                                 p.parent.process_name if p.parent != None else 'n/a'),
                                    p.process_name,
                                    p.process_imphash,
                                    p.process_cmd_line if p.process_cmd_line != '' else 'n/a',
                                    dll.dll_name,
                                    dll.dll_path,
                                    dll.dll_imphash,
                                    'KNOWN',   # process status
                                    'UNKNOWN',  # DLL status
                                    str(0), # Baseline FOO
                                    str(image_foo)]) # Image FOO
                else:
                    # known DLL

                    # identify DLLs additionally loaded compared to baseline proc
                    found_in_baseline_process = False
                    for bdll in baseline_process.dlls:
                        if dll.is_same_as(bdll, compare_imphash):
                            found_in_baseline_process = True
                            image_foo = -1
                            for image_dll_entry in image_dlls_statistics:
                                if dll.is_same_as(image_dll_entry['dll'], compare_imphash):
                                    image_foo = image_dll_entry['frequency_of_occurence']
                            records.append([str(p.pid),
                                            "%d (%s)" % (p.ppid,
                                                         p.parent.process_name if p.parent != None else 'n/a'),
                                            p.process_name,
                                            p.process_imphash,
                                            p.process_cmd_line if p.process_cmd_line != '' else 'n/a',
                                            dll.dll_name,
                                            dll.dll_path,
                                            dll.dll_imphash,
                                            'KNOWN',  # process status
                                            'KNOWN',  # DLL status
                                            str(baseline_dll_entry['frequency_of_occurence']), # Baseline FO
                                            str(image_foo)])  # Image FOO
                            break
                    if not found_in_baseline_process:
                        image_foo = -1
                        for image_dll_entry in image_dlls_statistics:
                            if dll.is_same_as(image_dll_entry['dll'], compare_imphash):
                                image_foo = image_dll_entry['frequency_of_occurence']
                        records.append([str(p.pid),
                                        "%d (%s)" % (p.ppid,
                                                     p.parent.process_name if p.parent != None else 'n/a'),
                                        p.process_name,
                                        p.process_imphash,
                                        p.process_cmd_line if p.process_cmd_line != '' else 'n/a',
                                        dll.dll_name,
                                        dll.dll_path,
                                        dll.dll_imphash,
                                        'KNOWN',  # process status
                                        'ADDITIONAL',  # DLL status
                                        str(baseline_dll_entry['frequency_of_occurence']), # Baseline FO
                                        str(image_foo)])  # Image FOO
    print("PROCESSES")
    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)

def compare_drivers(baseline: list,
                    image_to_check: list,
                    compare_imphash: bool,
                    show_known: bool,
                    output_handle: object):
    unknown_drivers = []
    known_drivers = []
    for drv in image_to_check.drivers:
        found = False
        for bdrv in baseline.drivers:
            if drv.is_same_as(bdrv, compare_imphash):
                found = True
                break

        if found:
            known_drivers.append(drv)
        else:
            unknown_drivers.append(drv)

    headers = ['STATUS', 'NAME', 'SIZE', 'IMPHASH', 'PATH']
    records = []
    for drv in unknown_drivers:
        records.append(['UNKNOWN',
                        drv.driver_name,
                        hex(drv.driver_image_size),
                        drv.driver_imphash,
                        drv.driver_path])

    if show_known:
        for drv in known_drivers:
            records.append(['KNOWN',
                            drv.driver_name,
                            hex(drv.driver_image_size),
                            drv.driver_imphash,
                            drv.driver_path])

    # output results
    print("DRIVERS")
    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)

def compare_services(baseline: list,
                     image_to_check: list,
                     compare_owner: bool,
                     compare_state: bool,
                     show_known: bool,
                     output_handle: object):
    unknown_services = []
    known_services = []

    for svc in image_to_check.services:
        found = False
        for bsvc in baseline.services:
            if svc.is_same_as(service = bsvc,
                              compare_owner = compare_owner,
                              compare_state = compare_state):
                found = True
        if not found:
            unknown_services.append(svc)
        else:
            known_services.append(svc)

    # Unknown services
    headers = ['STATUS', 'NAME', 'DISPLAY', 'STATE', 'TYPE', 'START', 'OWNER', 'BINARY']
    records = []
    for svc in unknown_services:
        records.append(['UNKNOWN',
                        svc.service_name,
                        svc.service_displayname,
                        svc.service_state,
                        svc.service_type,
                        svc.service_start,
                        svc.service_process_owner,
                        svc.service_process_binary])

    if show_known:
        for svc in known_services:
            records.append(['KNOWN',
                            svc.service_name,
                            svc.service_displayname,
                            svc.service_state,
                            svc.service_type,
                            svc.service_start,
                            svc.service_process_owner,
                            svc.service_process_binary])

    # output results
    print('SERVICES')
    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)

# create the logger object
logger = logging.getLogger('')

# create console handler and set level to info
handler = logging.StreamHandler()
handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# create debug file handler and set level to debug
handler = logging.FileHandler(os.path.join('.', "all.log"),"w")
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-b', '--baseline', help='The baseline image')
parser.add_argument('-i', '--image', help='The image to analyze')
parser.add_argument('-d', '--imagedir', help='The directory with images to analyze. Used for stacking')
parser.add_argument('-o', '--output', help='The output file where the results are to be saved')
parser.add_argument('-proc', action='store_true', help='Process analysis & DLL analysis')
parser.add_argument('-drv', action='store_true', help='Driver analysis')
parser.add_argument('-svc', action='store_true', help='Service analysis')
parser.add_argument('-procstack', action='store_true', help='Perform process stacking on the image(s)')
parser.add_argument('-dllstack', action='store_true', help='Perform DLL stacking on the image(s)')
parser.add_argument('-drvstack', action='store_true', help='Perform driver stacking on the image(s)')
parser.add_argument('-svcstack', action='store_true', help='Perform service stacking on the image(s)')
parser.add_argument('--imphash', action='store_true', help='Also compare import hashes')
parser.add_argument('--owner', action='store_true', help='Also compare process owners')
parser.add_argument('--cmdline', action='store_true', help='Also compare process commandlines')
parser.add_argument('--state', action='store_true', help='Also compare service states')
parser.add_argument('--showknown', action='store_true', help='Include known items in the output (prcesses, dlls, driver, services)')
parser.add_argument('--savebaseline', action='store_true', help='Save the baseline results of the analysis to a JSON file')
parser.add_argument('--loadbaseline', action='store_true', help='Load the baseline results of the analysis from a JSON file')
parser.add_argument('--jsonbaseline', help='The JSON file where the baseline results are located')
args = parser.parse_args()

# initial checks

# if we don't have any arguments display the help
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(-1)

# we need an image file if we are not doing stacking
if args.image:
    if not os.path.exists(args.image) and not os.path.isfile(args.image):
        logger.error('Image is not a valid file')
        sys.exit(-1)

# we need a baseline image if we are not doing stacking
if args.baseline:
    if not os.path.exists(args.baseline) and not os.path.isfile(args.baseline):
        logger.error('Baseline image is not a valid file')
        sys.exit(-1)

# we need a baseline image files if we are not doing stacking and not loading
#  the baseline data from a JSON file
if not args.loadbaseline and not args.procstack and not args.dllstack and not args.drvstack and not args.svcstack:
    if not args.baseline or not os.path.exists(args.baseline) or not os.path.isfile(args.baseline):
        logger.error('Baseline image is not a valid file')
        sys.exit(-1)

# we need a directory where the images are stored if we are doing stacking
if args.procstack or args.dllstack or args.drvstack or args.svcstack:
    if os.path.exists(args.imagedir) and not os.path.isdir(args.imagedir):
        logger.error('Image parameter is not a directory')
        sys.exit(-1)

# if we are loading the baseline from a JSON file that file must exist
if args.loadbaseline:
    if not os.path.exists(args.jsonbaseline) and not os.path.isfile(args.jsonbaseline):
        logger.error('JSON Baseline image is not a valid file')
        sys.exit(-1)

# if we are saving the baseline to a JSON file that file mustn't exist
if args.savebaseline:
    if os.path.exists(args.jsonbaseline):
        logger.error('Baseline JSON already exists! Cannot be overwritten!')
        sys.exit(-1)

output_handle = sys.stdout
if args.output:
    f = None
    if os.path.exists(args.output):
        logger.error('The output file already exists! Cannot be overwritten!')
        sys.exit(-1)
    else:
        try:
            f = open(args.output,'w')
        except Exception as e:
            logger.error('Error while opening the output file specified!')
            sys.exit(-1)
    if f != None:
        output_handle = f

# Perform process comparison
if args.proc:
    logger.info('Processing baseline image')
    baseline_processes = BaselineProcessList()
    if args.loadbaseline:
        baseline_processes.from_json(args.jsonbaseline)
    else:
        baseline_processes.from_image(image = args.baseline)
    if args.savebaseline:
        jsonbaseline = open(args.jsonbaseline, 'w')
        jsonbaseline.write(baseline_processes.to_json())
        jsonbaseline.close()

    logger.info('Processing image to compare')
    image_to_check_processes = BaselineProcessList()
    image_to_check_processes.from_image(image = args.image)

    compare_processes(baseline = baseline_processes,
                      image_to_check = image_to_check_processes,
                      compare_imphash = args.imphash,
                      compare_owner = args.owner,
                      compare_cmdline = args.cmdline,
                      show_known = args.showknown,
                      output_handle = output_handle)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform driver comparison
if args.drv:
    logger.info('Processing baseline image')
    baseline_drivers = BaselineDriverList()
    if args.loadbaseline:
        baseline_drivers.from_json(args.jsonbaseline)
    else:
        baseline_drivers.from_image(image = args.baseline)

    if args.savebaseline:
        jsonbaseline = open(args.jsonbaseline, 'w')
        jsonbaseline.write(baseline_drivers.to_json())
        jsonbaseline.close()

    logger.info('Processing image to compare')
    image_to_check_drivers = BaselineDriverList()
    image_to_check_drivers.from_image(image = args.image)

    compare_drivers(baseline = baseline_drivers,
                    image_to_check = image_to_check_drivers,
                    compare_imphash = args.imphash,
                    show_known = args.showknown,
                    output_handle = output_handle)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform service comparison
if args.svc:
    logger.info('Processing baseline image')
    baseline_services = BaselineServiceList()
    if args.loadbaseline:
        baseline_services.from_json(args.jsonbaseline)
    else:
        baseline_services.from_image(image = args.baseline)

    if args.savebaseline:
        jsonbaseline = open(args.jsonbaseline, 'w')
        jsonbaseline.write(baseline_services.to_json())
        jsonbaseline.close()

    logger.info('Processing image to compare')
    image_to_check_services = BaselineServiceList()
    image_to_check_services.from_image(image = args.image)

    compare_services(baseline = baseline_services,
                     image_to_check = image_to_check_services,
                     compare_owner = args.owner,
                     compare_state = args.state,
                     show_known = args.showknown,
                     output_handle = output_handle)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform DLL stacking
if args.dllstack:
    global_dll_statistics = []
    # loop through files
    for f in os.listdir(args.imagedir):
        i = os.path.join(args.imagedir, f)
        if os.path.isfile(i):
            try:
                print('Processing: (%s)' % (i))
                processes_list = BaselineProcessList()
                processes_list.from_image(i)
                dll_statistics = processes_list.collect_dll_statistics(args.imphash)

                # loop through DLL stat entries
                for entry in dll_statistics:
                    found = False
                    # check if DLL is already known
                    for g_entry in global_dll_statistics:
                        if entry['dll'].is_same_as(g_entry['dll'],args.imphash):
                            # if known, add frequency of occurence to the global
                            #   list
                            print('FOUND: ' + entry['dll'].dll_name)
                            found = True
                            g_entry['frequency_of_occurence'] += entry['frequency_of_occurence']
                            if i not in g_entry['images']:
                                g_entry['images'].append(i)
                            break
                    if not found:
                        # if unknown add a new entry to the global list
                        print('NEW: ' + entry['dll'].dll_name)
                        global_dll_statistics.append({
                            'dll': entry['dll'],
                            'frequency_of_occurence': entry['frequency_of_occurence'],
                            'images': [i]
                        })

            except Exception as e:
                print(str(e))
                pass

    # output results
    print("DLL FREQUENCY OF OCCURENCE")
    headers = ['FoO', 'IMPHASH', 'IMAGES', 'DLL NAME', 'DLL PATH']
    records = []
    for entry in global_dll_statistics:
        records.append([str(entry['frequency_of_occurence']),
                        entry['dll'].dll_imphash,
                        ';'.join(entry['images']),
                        entry['dll'].dll_name,
                        entry['dll'].dll_path])

    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform process stacking
if args.procstack:
    global_process_statistics = []

    # loop through files
    for f in os.listdir(args.imagedir):
        i = os.path.join(args.imagedir, f)
        if os.path.isfile(i):
            try:
                logger.info('Processing: (%s)' % (i))
                processes_list = BaselineProcessList()
                processes_list.from_image(i)
                process_statistics = processes_list.collect_process_statistics(compare_imphash = args.imphash,
                                                                               compare_owner = args.owner,
                                                                               compare_cmdline = args.cmdline)
                # loop through process statistics entries
                for entry in process_statistics:
                    found = False
                    # check if process is already known
                    for g_entry in global_process_statistics:
                        if entry['process'].is_same_as(process = g_entry['process'],
                                                       compare_imphash = args.imphash,
                                                       compare_owner = args.owner,
                                                       compare_cmdline = args.cmdline):
                            # if known add frequency of occurence to the global
                            #   list
                            logger.debug('FOUND: ' + entry['process'].process_name)
                            found = True
                            g_entry['frequency_of_occurence'] += entry['frequency_of_occurence']
                            if i not in g_entry['images']:
                                g_entry['images'].append(i)
                            break
                    if not found:
                        # if unknown add new entry to the global list
                        logger.debug('NEW: ' + entry['process'].process_name)
                        global_process_statistics.append({
                            'process': entry['process'],
                            'frequency_of_occurence': entry['frequency_of_occurence'],
                            'images': [i]
                        })

            except Exception as e:
                print(str(e))
                pass

    # output results
    print("PROCESS FREQUENCY OF OCCURENCE")
    headers = ['FoO', 'IMPHASH', 'IMAGES', 'PROCESS NAME', 'PROCESS CMD LINE']
    records = []
    for entry in global_process_statistics:
        records.append([str(entry['frequency_of_occurence']),
                        entry['process'].process_imphash,
                        ';'.join(entry['images']),
                        entry['process'].process_name,
                        entry['process'].process_cmd_line])

    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform service stacking
if args.svcstack:
    global_service_statistics = []

    # loop through files
    for f in os.listdir(args.imagedir):
        i = os.path.join(args.imagedir, f)
        if os.path.isfile(i):
            try:
                logger.info('Processing: (%s)' % (i))
                services_list = BaselineServiceList()
                services_list.from_image(i)
                service_statistics = services_list.collect_service_statistics(compare_owner = args.owner,
                                                                              compare_state = args.state)
                # loop through service statistics entries
                for entry in service_statistics:
                    found = False
                    # check if service is already known
                    for g_entry in global_service_statistics:
                        if entry['service'].is_same_as(service = g_entry['service'],
                                                       compare_owner = args.owner,
                                                       compare_state = args.state):
                            # if known add frequency of occurence to the global
                            #   list
                            logger.debug('FOUND: ' + entry['service'].service_name)
                            found = True
                            g_entry['frequency_of_occurence'] += entry['frequency_of_occurence']
                            if i not in g_entry['images']:
                                g_entry['images'].append(i)
                            break
                    if not found:
                        # if unknown add new entry to the global list
                        logger.debug('NEW: ' + entry['service'].service_name)
                        global_service_statistics.append({
                            'service': entry['service'],
                            'frequency_of_occurence': entry['frequency_of_occurence'],
                            'images': [i]
                        })

            except Exception as e:
                print(str(e))
                pass

    # output results
    print("SERVICE FREQUENCY OF OCCURENCE")
    headers = ['FoO', 'IMAGES', 'SERVICE NAME', 'SERVICE DISPLAY', 'SERVICE TYPE', 'SERVICE START', 'SERVICE STATE', 'SERVICE PROCESS OWNER', 'SERVICE BINARY']
    records = []
    for entry in global_service_statistics:
        records.append([str(entry['frequency_of_occurence']),
                        ';'.join(entry['images']),
                        entry['service'].service_name,
                        entry['service'].service_displayname,
                        entry['service'].service_type,
                        entry['service'].service_start,
                        entry['service'].service_state,
                        entry['service'].service_process_owner,
                        entry['service'].service_process_binary,])

    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)

# Perform driver stacking
if args.drvstack:
    global_driver_statistics = []

    # loop through files
    for f in os.listdir(args.imagedir):
        i = os.path.join(args.imagedir, f)
        if os.path.isfile(i):
            try:
                logger.info('Processing: (%s)' % (i))
                drivers_list = BaselineDriverList()
                drivers_list.from_image(i)
                driver_statistics = drivers_list.collect_driver_statistics(compare_imphash = args.imphash)
                # loop through driver statistics entries
                for entry in driver_statistics:
                    found = False
                    # check if driver is already known
                    for g_entry in global_driver_statistics:
                        if entry['driver'].is_same_as(driver = g_entry['driver'],
                                                      compare_imphash = args.imphash):
                            # if known add frequency of occurence to the global
                            #   list
                            logger.debug('FOUND: ' + entry['driver'].driver_name)
                            found = True
                            g_entry['frequency_of_occurence'] += entry['frequency_of_occurence']
                            if i not in g_entry['images']:
                                g_entry['images'].append(i)
                            break
                    if not found:
                        # if unknown add new entry to the global list
                        logger.debug('NEW: ' + entry['driver'].driver_name)
                        global_driver_statistics.append({
                            'driver': entry['driver'],
                            'frequency_of_occurence': entry['frequency_of_occurence'],
                            'images': [i]
                        })

            except Exception as e:
                print(str(e))
                pass

    # output results
    print("DRIVER FREQUENCY OF OCCURENCE")
    headers = ['FoO', 'IMAGES', 'DRIVER NAME', 'DRIVER IMPHASH', 'DRIVER IMAGE SIZE', 'DRIVER PATH']
    records = []
    for entry in global_driver_statistics:
        records.append([str(entry['frequency_of_occurence']),
                        ';'.join(entry['images']),
                        entry['driver'].driver_name,
                        entry['driver'].driver_imphash,
                        hex(entry['driver'].driver_image_size),
                        entry['driver'].driver_path])

    output_to_csv(file_handle = output_handle,
                  headers = headers,
                  records = records)
    if output_handle != sys.stdout:
        output_handle.close()
    sys.exit(0)
