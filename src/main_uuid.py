import os
import sys
import json
import time
import signal
import fnmatch
import logging
import argparse
from multiprocessing import Process, JoinableQueue, active_children
from uuid_extractor import UUIDExtractor

# Number of (multiprocessing) processes.
NUMBER_OF_PROCESSES = 5

# Status message constants for main thread.
STATUS_LOGGING = 'logging'
STATUS_ERROR = 'error'
STATUS_DONE = 'done'

KEY_UUID_FROM_STRING = 'uuid_from_string'
KEY_UUID_INIT = 'uuid_from_init'
KEY_UUID_FORMAT_STRING = 'uuid_format_string'

class UUIDExtractorMain:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Extract UUIDs.'
        )
        self.fn_initialise_argparser()
        
        # Set up directory paths.
        self.curr_dir = os.path.dirname(os.path.realpath(__file__))
        self.base_dir = os.path.abspath(os.path.join(
            self.curr_dir,
            '..'
        ))
        self.io_dir = os.path.abspath(os.path.join(
            self.base_dir,
            'input_output'
        ))
        if not os.path.isdir(self.io_dir):
            os.mkdir(self.io_dir)
        self.log_dir = os.path.abspath(os.path.join(
            self.base_dir,
            'logs'
        ))
        if not os.path.isdir(self.log_dir):
            os.mkdir(self.log_dir)
        date_time = time.strftime("%Y-%m-%d_%H-%M")
        self.error_log = os.path.join(
            self.log_dir,
            'error_' + date_time + '.log'
        )
        self.io_tmp_dir = os.path.abspath(os.path.join(
            self.io_dir,
            'tmp'
        ))
        if not os.path.isdir(self.io_tmp_dir):
            os.mkdir(self.io_tmp_dir)
        self.config_dir = os.path.abspath(os.path.join(
            self.base_dir,
            'config'
        ))
        self.res_dir = os.path.abspath(os.path.join(
            self.base_dir,
            'resources'
        ))

        self.fn_perform_initial_checks()
        
    def fn_perform_initial_checks(self):
        # Read in trace params.
        trace_params_json_file = os.path.abspath(os.path.join(
            self.config_dir,
            'extractor_params.json'
        ))
        if not (os.path.isfile(trace_params_json_file)):
            logging.critical(
                'Trace params file not found at '
                + trace_params_json_file
            )
            sys.exit(1)
        with open(trace_params_json_file) as f0:
            self.trace_params = json.loads(f0.read())
        # Double check that trace parameters are ok.
        self.fn_check_trace_params_object()
            
        # Read in special cases.
        named_special_case_json_file = os.path.join(
            self.res_dir,
            'android_named_object_links.json'
        )
        if not (os.path.isfile(named_special_case_json_file)):
            logging.critical(
                'Named object links file not found at '
                + named_special_case_json_file
            )
            sys.exit(1)
        with open(named_special_case_json_file) as f1:
            self.named_special_case_object = json.loads(f1.read())
        nonnamed_special_case_json_file = os.path.join(
            self.res_dir,
            'android_nonnamed_object_links.json'
        )
        if not (os.path.isfile(nonnamed_special_case_json_file)):
            logging.critical(
                'Non-named object links file not found at '
                + nonnamed_special_case_json_file
            )
            sys.exit(1)
        with open(nonnamed_special_case_json_file) as f2:
            self.nonnamed_special_case_object = json.loads(f2.read())
    
    def fn_check_trace_params_object(self):
        # Every trace must have a "from", i.e., a starting point.
        if 'from' not in self.trace_params:
            logging.critical(
                'Trace file does not specify starting point(s).'
            )
            sys.exit(1)
        if 'register' not in self.trace_params['from']:
            logging.critical(
                'Register for trace-from must be specified.'
            )
            sys.exit(1)
        if self.trace_params['from']['register'] == 'argto':
            if 'argindex' not in self.trace_params['from']:
                logging.critical(
                    'Argto must specify argindex.'
                )
                sys.exit(1)
        # If trace type is "path", then make sure there is a "to".
        trace_type = self.trace_params['type']
        if trace_type == 'path':
            if 'to' not in self.trace_params:
                logging.critical(
                    'Trace type is set to "path", but no end points given.'
                )
                sys.exit(1)

    def fn_initialise_argparser(self):
        self.parser.add_argument(
            '-f',
            '--file',
            help='Get APK list from file. '
                 + 'File must contain absolute paths to APKs.'
        )
        self.parser.add_argument(
            '-d',
            '--dir',
            help='Enumerate APKs in a directory. '
                 + 'Argument must specify absolute path to '
                 + 'directory.'
        )
        self.parser.add_argument(
            '-a',
            '--apk',
            help='Extract from a single APK.'
        )
    
    def fn_parse_args_and_populate_apk_list(self):
        apk_list = []
        bool_get_single_apk = False
        bool_get_apks_from_file = False
        bool_get_apks_from_directory = False
        args = self.parser.parse_args()

        if args.file:
            bool_get_apks_from_file = True
        if args.dir:
            bool_get_apks_from_directory = True
        if args.apk:
            bool_get_single_apk = True
        
        if ((bool_get_apks_from_file == False) and 
                (bool_get_apks_from_directory == False) and 
                (bool_get_single_apk == False)):
            logging.error(
                'Either a path to a single APK, '
                + 'a file containing a list of APKS, '
                + 'or a path to a directory containing APKS '
                + 'must be specified.'
            )
            sys.exit(1)
        if ((bool_get_apks_from_file == True) and 
                (bool_get_apks_from_directory == True) and 
                (bool_get_single_apk == True)):
            logging.error(
                'Specify a path to a single APK, '
                + 'a file containing a list of APKS, '
                + 'or a path to a directory containing APKS '
                + '(not all three).'
            )
            sys.exit(1)
        
        if bool_get_apks_from_directory == True:
            if not os.path.isdir(args.dir):
                logging.error('Directory does not exist.')
                sys.exit(1)
            for root, dirnames, filenames in os.walk(args.dir):
                for filename in fnmatch.filter(filenames, '*.apk'):
                    apk_list.append(os.path.join(root, filename))
            if apk_list == []:
                print('No APK files found.')
                sys.exit(0)
        elif bool_get_apks_from_file == True:
            if not os.path.isfile(args.file):
                logging.error('APK list file does not exist.')
                sys.exit(1)
            with open(args.file) as f:
                files = f.read().splitlines()
                for file in files:
                    if file.strip() != '':
                        apk_list.append(file.strip())
            if apk_list == []:
                print('No APK files found.')
                sys.exit(0)
        elif bool_get_single_apk == True:
            if not os.path.isfile(args.apk):
                logging.error('APK not found.')
                sys.exit(1)
            apk_list.append(args.apk)
        
        final_apk_list = []
        for apk_file in apk_list:
            raw_filename = self.fn_get_filename_from_path(apk_file)
            outfile = os.path.join(
                self.io_tmp_dir,
                raw_filename.replace('.apk', '.json')
            )
            if not os.path.isfile(outfile):
                final_apk_list.append(apk_file)
        return final_apk_list

    def fn_main(self):
        apk_list = self.fn_parse_args_and_populate_apk_list()
        # Keep track of the number of processes we create.
        num_processes = 0

        if apk_list == []:
            print('All APK files checked.')
            sys.exit(0)

        length_apk_list = len(apk_list)/NUMBER_OF_PROCESSES
        length_apk_list = int(length_apk_list)
        print(
            'Total number of APKs: ' 
            + str(len(apk_list))
            + '\nApproximate number of APKs per thread: '
            + str(length_apk_list)
        )

        # Free up memory
        checked_apks = None

        # Create two process queues: 
        #  one for sending data to, and one for receiving data from,
        #  the worker process(es).
        process_extractor_send_queue = JoinableQueue()
        process_extractor_receive_queue = JoinableQueue()

        # List for keeping track of processes.
        self.process_list = []
        # Create worker processes.
        for i in range(0, NUMBER_OF_PROCESSES):
            worker_uuid_process = UUIDExtractor(
                self.trace_params,
                self.named_special_case_object,
                self.nonnamed_special_case_object
            )
            worker = Process(
                target=worker_uuid_process.fn_main,
                args=(
                    process_extractor_send_queue,
                    process_extractor_receive_queue,
                    num_processes
                )
            )
            worker.start()
            self.process_list.append(worker)
            num_processes += 1

        apks_to_check = 0
        # Send work to worker process.
        for match in apk_list:
            if os.path.isfile(match):
                apks_to_check += 1
                process_extractor_send_queue.put(str(match))
            else:
                apk_list.remove(match)

        if os.path.isfile(self.error_log):
            fo_error = open(self.error_log, 'a')
        else:
            fo_error = open(self.error_log, 'w')
        completed_apk_count = 0

        while True:
            # Get information sent by worker process.
            [analysed_file, pkg, status, result] = process_extractor_receive_queue.get()
            process_extractor_receive_queue.task_done()
            # Analyse the output string.
            if status == STATUS_ERROR:
                print('\n Error encountered with ' + analysed_file 
                      + ': ' + result + '\n')
                # Log the error to a separate file.
                fo_error.write(analysed_file+','+result+'\n')
                completed_apk_count += 1
            elif status == STATUS_LOGGING:
                print(result)
            elif status == STATUS_DONE:
                print('\n Finished analysing ' + analysed_file 
                      + ' with result ' + str(result) + '\n')
                # Write the output to temporary JSON.
                raw_filename = self.fn_get_filename_from_path(analysed_file)
                filename_no_ext = raw_filename.replace('.apk', '')
                json_obj = {}
                json_obj[filename_no_ext] = {}
                json_obj[filename_no_ext]['pkg'] = pkg
                json_obj[filename_no_ext]['uuids'] = result
                outfile = os.path.join(
                    self.io_tmp_dir,
                    raw_filename.replace('.apk', '.json')
                )
                with open(outfile, 'w') as f:
                    json.dump(json_obj, f, indent=4)
                completed_apk_count += 1
            else:
                print('Unhandled condition from worker.')
            

            # Check if any processes have become zombies.
            if len(active_children()) < NUMBER_OF_PROCESSES:
                for p in self.process_list:
                    if not p.is_alive():
                        self.process_list.remove(p)
                        # Create a new process in its place.
                        worker_uuid_process = UUIDExtractor(
                            self.trace_params,
                            self.named_special_case_object,
                            self.nonnamed_special_case_object
                        )
                        replacement_worker = Process(
                            target=worker_uuid_process.fn_main,
                            args=(
                                process_extractor_send_queue,
                                process_extractor_receive_queue,
                                num_processes
                            )
                        )
                        replacement_worker.start()
                        self.process_list.append(replacement_worker)
                        num_processes += 1

            # Check if all APKs have been analysed.            
            if completed_apk_count == apks_to_check:
                break

        print('All done.')

        # Tell child processes to stop
        for i in range(NUMBER_OF_PROCESSES):
            process_extractor_send_queue.put('STOP')

        # Collate.
        self.fn_collate_json()
        
    def fn_handle_termination(self):
        for p in self.process_list:
            p.terminate()
            
    def fn_get_filename_from_path(self, path):
        return os.path.basename(path)
    
    def fn_collate_json(self):
        print('Collating...')
        main_output_file = os.path.join(
            self.io_dir,
            'uuid_extractor_output.json'
        )
        main_output_obj = {}
        
        out_json_files = []
        for root, dirnames, filenames in os.walk(self.io_tmp_dir):
            for filename in fnmatch.filter(filenames, '*.json'):
                out_json_files.append(os.path.join(root, filename))
                
        for json_file in out_json_files:
            with open(json_file) as f:
                json_obj = json.load(f)
                main_output_obj.update(json_obj)
                
        with open(main_output_file, 'w') as out:
            json.dump(main_output_obj, out, indent=4)
                
#=====================================================#
if __name__ == '__main__':
    UUIDExtractorMain().fn_main()
