import os
import re
import sys
import json
import timeit
import collections
from time import sleep
from multiprocessing import JoinableQueue
from androguard.misc import *
from androguard.core import *
from androguard import session

# Timing-related.
MAX_RUNTIME = 1800

# Related to the instruction queue.
QUEUE_APPEND = 1
QUEUE_PREPEND = 2

# Status message constants for main thread.
STATUS_LOGGING = 'logging'
STATUS_ERROR = 'error'
STATUS_DONE = 'done'

KEY_UUID_FROM_STRING = 'uuid_from_string'
KEY_UUID_INIT = 'uuid_from_init'
KEY_UUID_FORMAT_STRING = 'uuid_format_string'

# Trace types.
TRACE_TYPE_VALUE = 'value'
TRACE_TYPE_PATH = 'path'

# Custom constants.
METHOD_INTERNAL = 0
METHOD_EXTERNAL = 1
METHOD_EMPTY = 2

# Dalvik opcodes and operand indices.
MOVE_OPCODES = [0x01, 0x02, 0x05, 0x07, 0x08]
MOVE_OPERAND_INDEX = 0
MOVE_OPERAND_SOURCE_INDEX = 1
MOVE_RESULT_OPCODES = [0x0A, 0x0B, 0x0C]
MOVE_RESULT_OPERAND_INDEX = 0
RETURN_OPCODES = [0x0F, 0x10, 0x11]
RETURN_OPERAND = 0
CONST_DECL_OPCODES = [0x12, 0x13, 0x14, 0x15,
                      0x16, 0x17, 0x18, 0x19,
                      0x1A, 0x1B, 0x1C]
CONST_WIDE_OPCODES = [0x16, 0x17, 0x18, 0x19]
CONST_OPERAND_INDEX = 0
NEW_INSTANCE_OPCODES = [0x22]
NEW_INSTANCE_OPERAND_INDEX = 0
NEW_ARRAY_OPCODES = [0x23]
NEW_ARRAY_OPERAND_INDEX = 0
FILLED_ARRAY_OPCODES = [0x24, 0x25]
GOTO_OPCODES = [0x28, 0x29, 0x2A]
GOTO_OPERAND_INDEX = 0
COMPARE_OPCODES = [0x2D, 0x2E, 0x2F, 0x30, 0x31]
COMPARE_OPERAND_INDEX = 0
COMPARE_OPERAND_SOURCE1_INDEX = 1
COMPARE_OPERAND_SOURCE2_INDEX = 2
CONDITIONAL_OPCODES = [0x32, 0x33, 0x34, 0x35,
                       0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D]
CONDITIONAL_OPERAND_INDEX = 0
CONDITIONAL_DESTINATION = 1
AGET_OPCODES = [0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A]
AGET_OPERAND_INDEX = 0
AGET_OPERAND_SOURCE_INDEX = 1
APUT_OPCODES = [0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51]
APUT_OPERAND_INDEX = 1
APUT_OPERAND_SOURCE_INDEX = 0
IGET_OPCODES = [0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58]
IGET_OPERAND_INDEX = 0
IGET_OPERAND_SOURCE_INDEX = 2
IPUT_OPCODES = [0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F]
IPUT_OPERAND_FIELD_INDEX = 2
IPUT_OPERAND_SOURCE_INDEX = 0
SGET_OPCODES = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]
SGET_OPERAND_INDEX = 0
SGET_OPERAND_SOURCE_INDEX = 1
SPUT_OPCODES = [0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D]
SPUT_OPERAND_SOURCE_INDEX = 0
SPUT_OPERAND_INDEX = 1
INVOKE_OPCODES = [0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78]
INVOKE_RANGE_OPCODES = [0x74, 0x75, 0x76, 0x77, 0x78]
INVOKE_VIRTUAL_OPCODES = [0x6E, 0x74]
INVOKE_SUPER_OPCODES = [0x6F, 0x75]
INVOKE_DIRECT_OPCODES = [0x70, 0x76]
INVOKE_STATIC_OPCODES = [0x71, 0x77]
INVOKE_INTERFACE_OPCODES = [0x72, 0x78]
GET_TO_PUT_OFFSET = 0x7
PUT_TO_GET_OFFSET = -0x7
OPERATION_OPCODES = range(0x7B, 0xE2)
OPERATION_OPERAND_INDEX = 0
OPERATION_OPERAND_SOURCE_INDEX = 1

# Access flags.
ACCESS_FLAG_PUBLIC = 0x1
ACCESS_FLAG_PRIVATE = 0x2
ACCESS_FLAG_PROTECTED = 0x4
ACCESS_FLAG_STATIC = 0x8
ACCESS_FLAG_FINAL = 0x10
ACCESS_FLAG_SYNC = 0x20
ACCESS_FLAG_BRIDGE = 0x40
ACCESS_FLAG_VARARGS = 0x80
ACCESS_FLAG_NATIVE = 0x100
ACCESS_FLAG_INTERFACE = 0x200
ACCESS_FLAG_ABSTRACT = 0x400
ACCESS_FLAG_STRICT = 0x800
ACCESS_FLAG_SYNTH = 0x1000
ACCESS_FLAG_ENUM = 0x4000
ACCESS_FLAG_UNUSED = 0x8000
ACCESS_FLAG_CONSTRUCTOR = 0x10000
ACCESS_FLAG_SYNC2 = 0x20000

# Operand types.
OPERAND_REGISTER = 0
OPERAND_LITERAL = 1
OPERAND_RAW = 2
OPERAND_OFFSET = 3
OPERAND_KIND = 0x100


class UUIDExtractor:
    def __init__(self, trace_obj, special_named, special_nonnamed):
        # Instruction queue.
        self.instruction_queue = collections.deque()
        
        # Initialise values.
        self.fn_reset_values()
        
        # Trace object.
        self.trace_params = trace_obj
        
        # Objects for special case handling.
        self.named_special_case_object = special_named
        self.nonnamed_special_case_object = special_nonnamed
        
    def fn_reset_values(self):
        # Reset values for each new APK.
        self.androguard_a = None
        self.androguard_d = None
        self.androguard_dx = None
        self.apk_package = None
        self.start_time = timeit.default_timer()
        self.instruction_queue.clear()
        self.checked_methods = set()
        self.uuid_parts = {}
        self.stored_returns = {}
        self.current_counter = 0
        self.outputs = None
        # Initialise the trace type. A value analysis returns a value.
        # A path analysis returns true/false
        self.trace_type = None
        
    def fn_main(self, in_queue, out_queue, process_id):
        for queue_input in iter(in_queue.get, 'STOP'):
            # First, reset values per APK.
            self.fn_reset_values()            
            # Get path to apk from parent.
            filepath = str(queue_input).strip()
            # Send logging message to parent.
            out_queue.put([
                filepath,
                None,
                STATUS_LOGGING,
                'Analysing ' + filepath + ' in thread ' + str(process_id)
            ])
            
            # Get default Androguard session.
            sess = get_default_session()
            
            # Try to execute AnalyzeAPK.
            try:
                self.androguard_a, self.androguard_d, self.androguard_dx = \
                    AnalyzeAPK(filepath, session=sess)
            except Exception as e:
                out_queue.put([
                    filepath,
                    None,
                    STATUS_ERROR,
                    'AnalyzeAPK error: ' + str(e)
                ])
                in_queue.task_done()
                sess.reset()
                sleep(0.1)
                continue
            
            # None of the outputs should be None.
            if ((self.androguard_a == None) or 
                    (self.androguard_d == None) or 
                    (self.androguard_dx == None)):
                out_queue.put([
                    filepath,
                    None,
                    STATUS_ERROR,
                    'a, d or dx is None.'
                ])
                in_queue.task_done()
                sess.reset()
                sleep(0.1)
                continue
            
            # Get the package name.
            self.apk_package = self.androguard_a.get_package()
            
            try:
                self.fn_search_apk_for_uuids()
            except Exception as e:
                out_queue.put([
                    filepath,
                    None,
                    STATUS_ERROR,
                    'Analysis error: ' + str(e)
                ])
                in_queue.task_done()
                sess.reset()
                sleep(0.1)
                continue

            # If there were no errors, we should get to this point.
            out_queue.put([
                filepath,
                self.apk_package,
                STATUS_DONE,
                self.outputs
            ])
            in_queue.task_done()
            sess.reset()
            sleep(0.1)
            continue
    
    """ ================ Preliminary analysis phase ================== """    
    def fn_search_apk_for_uuids(self):
        # Set parameters based on trace object.
        self.fn_set_initial_parameters()
        # First get the methods of interest.
        self.fn_get_starting_points_from_trace()
        if self.starting_points == []:
            return
        if self.start_register_type == 'argto':
            self.fn_start_analysing_argto()

    def fn_set_initial_parameters(self):
        self.trace_direction = self.trace_params['direction']
        self.trace_from_methods = self.trace_params['from']['methods']
        self.start_register_type = self.trace_params['from']['register']
        if self.start_register_type == 'argto':
            self.start_register_index = self.trace_params['from']['argindex']
        # Identify trace type.
        trace_type = self.trace_params['type']
        if trace_type == TRACE_TYPE_VALUE:
            self.trace_type = TRACE_TYPE_VALUE
            self.outputs = {}
        else:
            self.trace_type = TRACE_TYPE_PATH
            self.trace_to_methods = self.trace_params['to']['methods']
            self.outputs = ''
        
    def fn_get_starting_points_from_trace(self):
        trace_from = []
        for trace_from_method in self.trace_from_methods:
            [class_part, method_part, desc_part] = \
                self.fn_get_class_method_desc_from_string(trace_from_method)
            trace_from.extend(self.fn_get_calling_methods(
                class_part,
                method_part,
                desc_part
            ))
        self.starting_points = list(set(trace_from))
    
    def fn_start_analysing_argto(self):
        for starting_point_method in self.starting_points:
            for trace_from_method_string in self.trace_from_methods:
                if 'readCharacteristic' in trace_from_method_string:
                    src = 'Read'
                elif 'writeCharacteristic' in trace_from_method_string:
                    src = 'Write'
                elif 'getCharacteristic' in trace_from_method_string:
                    src = 'Get'
                elif 'setCharacteristicNotification' in trace_from_method_string:
                    src = 'NotifyIndicate'
                else:
                    src = 'Unknown'
                instr_reg = self.fn_analyse_argto_for_individual_method(
                    starting_point_method,
                    trace_from_method_string,
                    self.start_register_index
                )
                for element in instr_reg:
                    register = element[0]
                    index = element[1]
                    self.fn_determine_trace_route(
                        starting_point_method,
                        register,
                        index-1,
                        src=src
                    )

    """ ================= Main trace functions =================== """
    def fn_analyse_argto_for_individual_method(self, calling_method,
                                               called_method_string, reg_idx):
        """Identifies the instruction index and register used as argument."""
        argument_register = ''
        index = -1
        output = []
        list_instructions = list(calling_method.get_instructions())
        for index, instruction in enumerate(list_instructions):
            operands = None
            last_operand = None
            argument_register = ''
            if (instruction.get_op_value() not in INVOKE_OPCODES):
                continue
            operands = instruction.get_operands(0)
            last_operand = operands[-1][2]
            if called_method_string not in last_operand:
                continue
            if ((instruction.get_op_value() in INVOKE_OPCODES) and 
                    (reg_idx == (len(operands)-1))):
                argument_register = operands[reg_idx-1][1]
            else:
                argument_register = operands[reg_idx][1]
            if ((argument_register != '') and (index != -1)):
                output.append((argument_register, index))
                argument_register = ''
        return output
        
    def fn_determine_trace_route(self, method, register, index, val_id=-1, src=None):
        # Make sure we don't perform the same checks over and over again.
        method_string = self.fn_get_method_string_from_method(method)
        identifier_string = (method_string
                             + '#' + str(register) + '#' + str(index))
        if identifier_string in self.checked_methods:
            return
        self.checked_methods.add(identifier_string)
            
        # Identify whether this method takes an instance as first parameter.
        # Static methods do not. Instance methods do.
        isThis = None
        num_locals = 0
        try:
            num_locals = self.fn_get_locals(method)
            method.get_instructions()
            method_access_flags = method.get_access_flags()
            if ((ACCESS_FLAG_STATIC & method_access_flags) 
                    == ACCESS_FLAG_STATIC):
                isThis = False
            else:
                isThis = True
        except:
            isThis = None

        # Determine whether to trace internally or analyse calls to methods.
        if register > num_locals:
            self.fn_analyse_calls_to_method(
                method,
                register-num_locals,
                val_id,
                src
            )
        elif register < num_locals:
            self.fn_analyse_method_internally(
                method,
                register,
                index,
                val_id,
                src
            )
        else:
            if isThis == False:
                self.fn_analyse_calls_to_method(
                    method,
                    0,
                    val_id,
                    src
                )
            elif isThis == True:
                # Init analysis
                logging.info('METHOD INIT ANALYSIS TODO')
                pass
            else:
                logging.info('Unsupported right now! ' 
                      + method.get_class_name() + '   ' + method.get_name())

    def fn_analyse_calls_to_method(self, method, reg_position, val_id, src):
        [class_part, method_part, desc_part]= \
            self.fn_get_class_method_desc_from_method(method)
        all_classes = self.fn_get_subclasses(class_part)
        all_classes.append(class_part)
        for one_class in all_classes:
            self.fn_analyse_calls_to_individual_method(
                one_class,
                method_part,
                desc_part,
                reg_position,
                val_id,
                src
            )
        
    def fn_analyse_calls_to_individual_method(self, class_part, method_part,
                                              desc_part, reg_position, val_id, src):
        method_string = class_part + '->' + method_part + desc_part
        logging.info('Analysing calls to method: ' + method_string 
              + ' at position ' + str(reg_position))
        calling_methods = self.fn_get_calling_methods(
            class_part,
            method_part,
            desc_part
        )
        all_returns = []
        for calling_method in calling_methods:
            instr_reg = self.fn_analyse_argto_for_individual_method(
                calling_method,
                method_string,
                reg_position
            )
            for element in instr_reg:
                register = element[0]
                index = element[1]
                logging.info('Identified reg ' + str(register) 
                      + ' at index ' + str(index))
                self.fn_determine_trace_route(
                    calling_method,
                    register,
                    index-1,
                    val_id,
                    src
                )

    def fn_analyse_method_internally(self, method, register,
                                     index, val_id, src):
        method_string = self.fn_get_method_string_from_method(method)
        logging.info('Analysing ' + method_string + ' reg: ' 
              + str(register) + ' .index ' + str(index))
        instructions = list(method.get_instructions())
        for instr_index in range(index, -1, -1):
            instruction = instructions[instr_index]
            opcode = instruction.get_op_value()
            operands = instruction.get_operands()
            for operand_index, operand in enumerate(operands):
                if operand[0] != OPERAND_REGISTER:
                    continue
                if register != operand[1]:
                    continue
                action_check_output = self.fn_determine_register_handling(
                    method,
                    instr_index,
                    opcode,
                    operand_index,
                    val_id,
                    src
                )
                if action_check_output == False:
                    return
                elif action_check_output == True:
                    break

    def fn_determine_register_handling(self, method, instr_index,
                                       opcode, operand_index, val_id, src):
        instructions = list(method.get_instructions())
        instruction = instructions[instr_index]
        operands = instruction.get_operands()
        
        # Perform checks.
        if ((opcode in MOVE_OPCODES) and 
                (operand_index == MOVE_OPERAND_INDEX)):
            move_src = operands[MOVE_OPERAND_SOURCE_INDEX][1]
            self.fn_determine_trace_route(
                method,
                move_src,
                instr_index-1,
                val_id,
                src
            )
            return False
        elif ((opcode in MOVE_RESULT_OPCODES) and 
                (operand_index == MOVE_RESULT_OPERAND_INDEX)):
            self.fn_analyse_invoked_methods(
                method,
                instr_index-1,
                val_id,
                src,
                'M'
            )
            return False
        elif ((opcode in CONST_DECL_OPCODES) and 
                (operand_index == CONST_OPERAND_INDEX)):
            const_value = (operands)[1][-1]
            if type(const_value) is str:
                const_value = const_value.replace("'",'').replace('"','')
            # If the value identifier is set, then some other function wants
            #  this value for further processing. Add it to the value store
            #  and return.
            if val_id != -1:
                if val_id in self.stored_returns:
                    self.stored_returns[val_id].append(const_value)
                return False
            # If the value identifier is not set, then this may be a final
            #  value. Send it to be added to output.
            # First get the class within which it was found.
            method_string = self.fn_get_method_string_from_method(method)
            self.fn_add_uuid_string_to_output(
                KEY_UUID_FROM_STRING,
                const_value,
                method_string,
                src
            )
            return False
        elif ((opcode in NEW_INSTANCE_OPCODES) and 
                (operand_index == NEW_INSTANCE_OPERAND_INDEX)):
            # TODO
            return False
        elif ((opcode in NEW_ARRAY_OPCODES) and 
                (operand_index == NEW_ARRAY_OPERAND_INDEX)):
            # TODO
            return False
        elif ((opcode in AGET_OPCODES) and 
                (operand_index == AGET_OPERAND_INDEX)):
            aget_src = operands[AGET_OPERAND_SOURCE_INDEX][1]
            self.fn_determine_trace_route(
                method,
                aget_src,
                instr_index-1,
                val_id,
                src
            )
            return False
        elif ((opcode in APUT_OPCODES) and 
                (operand_index == APUT_OPERAND_INDEX)):
            aput_src = operands[APUT_OPERAND_SOURCE_INDEX][1]
            self.fn_determine_trace_route(
                method,
                aput_src,
                instr_index-1,
                val_id,
                src
            )
            return False
        elif ((opcode in IGET_OPCODES) and 
                (operand_index == IGET_OPERAND_INDEX)):
            iget_field = operands[IGET_OPERAND_SOURCE_INDEX][2]
            self.fn_find_field_put(iget_field, val_id, src)
            return False
        elif ((opcode in SGET_OPCODES) and 
                (operand_index == SGET_OPERAND_INDEX)):
            sget_field = operands[SGET_OPERAND_SOURCE_INDEX][2]
            self.fn_find_field_put(sget_field, val_id, src)
            return False
        elif (opcode in INVOKE_OPCODES):
            self.fn_analyse_invoked_methods(
                method,
                instr_index,
                val_id,
                src,
                'I'
            )
            # DO NOT RETURN FALSE.
            return True
        else:
            logging.info('OTHER' + str(operands))
            return True
    
    def fn_find_field_put(self, field, val_id, src):
        all_fields = self.fn_find_fields(field)
        for one_field in all_fields:
            for xref_writes in one_field.get_xref_write():
                method = xref_writes[1]
                instructions = list(method.get_instructions())
                for index, instruction in enumerate(instructions):
                    opcode = instruction.get_op_value()
                    if ((opcode not in IPUT_OPCODES) and 
                            (opcode not in SPUT_OPCODES)):
                        continue
                    operands = instruction.get_operands()
                    last_operand = operands[-1][-1]
                    if field not in last_operand:
                        continue
                    register = operands[0][1]
                    self.fn_determine_trace_route(
                        method,
                        register,
                        index-1,
                        val_id,
                        src
                    )

    def fn_analyse_invoked_methods(self, method, instr_index,
                                   val_id, src, itype):
        method_invocation_instruction = \
            list(method.get_instructions())[instr_index]
        operands = method_invocation_instruction.get_operands()
        invoked_method = ''.join(operands[-1][2].split(' '))
        logging.info('invoked ' + invoked_method)
        gatt_get_char = 'Landroid/bluetooth/BluetoothGattService;->' \
                        + 'getCharacteristic(Ljava/util/UUID;)' \
                        + 'Landroid/bluetooth/BluetoothGattCharacteristic;'
        uuid_from_string = 'Ljava/util/UUID;->' \
                           + 'fromString(Ljava/lang/String;)Ljava/util/UUID;'
        parcel_init = 'Landroid/os/ParcelUuid;-><init>(Ljava/util/UUID;)V'
        parcel_uuid_from_string = 'Landroid/os/ParcelUuid;->' \
                                  + 'fromString(Ljava/lang/String;)' \
                                  + 'Landroid/os/ParcelUuid;'
        parcel_get_uuid = 'Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;'
        uuid_init = 'Ljava/util/UUID;-><init>(JJ)V'
        char_get_uuid = 'Landroid/bluetooth/BluetoothGattCharacteristic;->' \
                        + 'getUuid()Ljava/util/UUID;'
        string_format = 'Ljava/lang/String;->format(Ljava/lang/String;' \
                        + '[Ljava/lang/Object;)Ljava/lang/String;'
        if gatt_get_char in invoked_method:
            input_reg_of_interest = operands[1][1]
        elif ((uuid_from_string in invoked_method) or 
                (parcel_uuid_from_string in invoked_method) or 
                (parcel_get_uuid in invoked_method)):
            input_reg_of_interest = operands[0][1]
        elif parcel_init in invoked_method:
            input_reg_of_interest = operands[1][1]
        elif uuid_init in invoked_method:
            self.fn_uuid_init_analysis(method, instr_index, src)
            return
        elif char_get_uuid in invoked_method:
            self.fn_check_for_uuid_equals(method, instr_index, src)
            return
        elif string_format in invoked_method:
            if itype == 'M':
                self.fn_analyse_formatted_string(method, instr_index, src)
            return
        else:
            [_, _, desc_part] = \
                self.fn_get_class_method_desc_from_string(invoked_method)
            if desc_part.split(')')[1] == 'Ljava/util/UUID;':
                if itype == 'M':
                    self.fn_analyse_return_of_uuid_method(invoked_method, src)
                    return
            logging.info('OTHER INVOKED METHOD ' + invoked_method)
            return
        logging.info('Now tracing reg ' + str(input_reg_of_interest))
        self.fn_determine_trace_route(
            method,
            input_reg_of_interest,
            instr_index-1,
            val_id,
            src
        )
    
    def fn_analyse_return_of_uuid_method(self, method_string, src):
        logging.info('Analysing return of method: ' + method_string)
        [class_part, method_part, desc_part] = \
            self.fn_get_class_method_desc_from_string(method_string)
        all_methods = self.fn_get_methods(class_part, method_part, desc_part)
        for methodanalysis in all_methods:
            try:
                method = methodanalysis.get_method()
                self.fn_analyse_return_of_method(method, -1, src)
            except:
                continue
            
    def fn_analyse_return_of_method(self, method, val_id, src):
        instructions = list(method.get_instructions())
        for index, instruction in enumerate(instructions):
            opcode = instruction.get_op_value()
            if opcode not in RETURN_OPCODES:
                continue
            operands = instruction.get_operands()
            returned_reg = operands[0][1]
            self.fn_determine_trace_route(
                method,
                returned_reg,
                index-1,
                val_id,
                src
            )
    
    def fn_analyse_formatted_string(self, method, instr_index, src):
        instructions = list(method.get_instructions())
        instruction = instructions[instr_index]
        operands = instruction.get_operands()
        string1_reg = operands[0][1]
        string2_reg = operands[1][1]
        
        string1 = str(self.current_counter)
        self.stored_returns[string1] = []
        self.current_counter += 1
        self.fn_determine_trace_route(
            method,
            string1_reg,
            instr_index-1,
            string1,
            src=src
        )
        
        string2 = str(self.current_counter)
        self.stored_returns[string2] = []
        self.current_counter += 1
        self.fn_determine_trace_route(
            method,
            string2_reg,
            instr_index-1,
            string2,
            src=src
        )
        
        if ((self.stored_returns[string1] == []) or 
                (self.stored_returns[string2] == [])):
            return
        
        method_string = self.fn_get_method_string_from_method(method)
        for str1 in self.stored_returns[string1]:
            for str2 in self.stored_returns[string2]:
                self.fn_format_uuid_string(str1, str2, method_string, src)
    
    def fn_format_uuid_string(self, string1, string2, method_string, src):
        string1 = str(string1).replace("'",'').replace('"','')
        string2 = str(string2).replace("'",'').replace('"','')
        if '%' in string1:
            if '%' in string2:
                return
            self.fn_create_formatted_uuid_string(string1, string2, method_string, src)
        if '%' in string2:
            if '%' in string1:
                return
            self.fn_create_formatted_uuid_string(string2, string1, method_string, src)
            
    def fn_create_formatted_uuid_string(self, string1, string2, method_string, src):
        if '%4s' in string1:
            if len(string2) == 4:
                self.fn_add_uuid_string_to_output(
                    KEY_UUID_FORMAT_STRING,
                    string1.replace('%4s', string2),
                    method_string,
                    src
                )
            else:
                logging.info('Incorrect length ' + string1 + ' ' 
                      + string2 + ' ' + str(len(string2)))
        elif '%s' in string1:
            self.fn_add_uuid_string_to_output(
                KEY_UUID_FORMAT_STRING,
                string1.replace('%s', string2),
                method_string,
                src
            )
        
    def fn_check_for_uuid_equals(self, method, instr_index, src):
        instructions = list(method.get_instructions())
        if len(instructions) < instr_index:
            return
        output_instruction = instructions[instr_index+1]
        if output_instruction.get_op_value() not in MOVE_RESULT_OPCODES:
            return
        output_reg = output_instruction.get_operands()[0][1]
        output_reg_string = ''
        for index in range(instr_index+2, len(instructions)):
            instruction = instructions[index]
            opcode = instruction.get_op_value()
            if opcode not in INVOKE_OPCODES:
                continue
            operands = instruction.get_operands()
            last_operand = operands[-1][2]
            if (('Ljava/util/UUID;->toString()Ljava/lang/String;' 
                    in last_operand) or 
                    ('Landroid/os/ParcelUuid;->toString()Ljava/lang/String;'
                    in last_operand)):
                output_instruction_string = instructions[index+1]
                output_operands = output_instruction_string.get_operands()
                output_reg_string = output_operands[0][1]
            if ('Ljava/lang/String;->equals(Ljava/lang/Object;)Z' 
                    not in last_operand):
                continue
            comparison_reg = None
            for op_index, operand in enumerate(operands):
                if operand[1] == output_reg_string:
                    if op_index == 0:
                        comparison_reg = operands[1][1]
                    else:
                        comparison_reg = operands[0][1]
            if comparison_reg == None:
                continue
            self.fn_determine_trace_route(
                method,
                comparison_reg,
                index-1,
                src=src
            )
        
    def fn_uuid_init_analysis(self, method, instr_index, src):
        uuid_init_instruction = \
            list(method.get_instructions())[instr_index]
        operands = uuid_init_instruction.get_operands()
        
        operand1_str = str(self.current_counter)
        self.stored_returns[operand1_str] = []
        self.current_counter += 1
        self.fn_determine_trace_route(
            method,
            operands[1][1],
            instr_index-1,
            operand1_str,
            src=src
        )
        
        operand2_str = str(self.current_counter)
        self.stored_returns[operand2_str] = []
        self.current_counter += 1
        self.fn_determine_trace_route(
            method,
            operands[3][1],
            instr_index-1,
            operand2_str,
            src=src
        )
        
        operand1s = self.stored_returns[operand1_str]
        operand2s = self.stored_returns[operand2_str]
        
        if ((operand1s == []) or (operand2s == [])):
            return
        
        method_string = self.fn_get_method_string_from_method(method)
        for operand1 in operand1s:
            for operand2 in operand2s:
                self.fn_create_init_uuid(operand1, operand2, method_string, src)
    
    def fn_create_init_uuid(self, operand1, operand2, method_string, src):
        # Check if either value is negative. If so, convert to unsigned.
        # Check first value.
        hex_value1 = (hex(operand1)).replace('0x', '').replace('L', '')
        str_value1 = str(hex_value1)
        if str_value1[0] == '-':
            operand1 = self.fn_convert_signed_to_unsigned(operand1)
        else:
            operand1 = str_value1
        # Check second value.
        hex_value2 = (hex(operand2)).replace('0x', '').replace('L', '')
        str_value2 = str(hex_value2)
        if str_value2[0] == '-':
            operand2 = self.fn_convert_signed_to_unsigned(operand2)
        else:
            operand2 = str_value2
        
        # Apply padding if needed.
        if ((len(operand1) + len(operand2)) == 32):
            intermediate_operand = operand1 + operand2
        elif ((len(operand1) + len(operand2)) < 32):
            padding_len = 32 - (len(operand1) + len(operand2))
            intermediate_operand = '0' * padding_len
            intermediate_operand = intermediate_operand + operand1 + operand2
        else:
            return
            
        if intermediate_operand != '':
            final_operand = intermediate_operand[0:8] \
                            + '-' \
                            + intermediate_operand[8:12] \
                            + '-' \
                            + intermediate_operand[12:16] \
                            + '-' \
                            + intermediate_operand[16:20] \
                            + '-' \
                            + intermediate_operand[20:]
        
        # Add to output object.
        self.fn_add_uuid_string_to_output(
            KEY_UUID_INIT,
            final_operand,
            method_string,
            src
        )

    """ ================= Androguard functions ================ """
    def fn_get_locals(self, method):
        num_registers = method.code.get_registers_size()
        num_parameter_registers = method.code.get_ins_size()
        num_local_registers = num_registers - num_parameter_registers
        return num_local_registers
        
    def fn_get_methods(self, class_part, method_part, desc_part):
        desc_part = desc_part.replace('(', '\(').replace(')', '\)')
        desc_part = desc_part.replace('$', '\$').replace('[', '\[')
        called_methods = self.androguard_dx.find_methods(
            class_part.replace('$', '\$').replace('_', '\_'),
            method_part.replace('_', '\_'),
            desc_part.replace('_', '\_')
            
        )
        return called_methods
        
    def fn_get_calling_methods(self, class_part, method_part, desc_part):
        called_methods = self.fn_get_methods(
            class_part,
            method_part,
            desc_part
        )
        calling_methods = set()
        for called_method in called_methods:
            for element in called_method.get_xref_from():
                calling_methods.add(element[1])
        return list(calling_methods)
    
    def fn_get_subclasses(self, class_name, recursive=True):
        subclasses = []
        all_classes = self.androguard_dx.find_classes('.')
        for one_class in all_classes:
            if one_class.is_external() == True:
                continue
            vmclass = one_class.get_vm_class()
            superclass = vmclass.get_superclassname()
            if superclass != class_name:
                continue
            subclass = vmclass.get_name()
            subclasses.append(subclass)
            if recursive == True:
                new_subclasses = self.fn_get_subclasses(subclass)
                for new_subclass in new_subclasses:
                    subclasses.append(new_subclass)
        return list(set(subclasses))
        
    def fn_find_fields(self, field):
        classname = field.split('->')[0].strip()
        fieldname_split = field.split('->')[1].strip()
        fieldname = fieldname_split.split(' ')[0].strip()
        fieldtype = fieldname_split.split(' ')[1].strip().replace('[', '\[')
        all_fields = self.androguard_dx.find_fields(
            classname.replace('$', '\$').replace('_', '\_'),
            fieldname.replace('$', '\$').replace('_', '\_'),
            fieldtype.replace('$', '\$').replace('_', '\_')
        )
        return all_fields
    
    """ ================== Utility functions ================== """
    def fn_get_filename_from_path(self, path):
        return os.path.basename(path)
        
    def fn_get_class_method_desc_from_string(self, string):
        class_part = '.'
        method_part = '.'
        desc_part = '.'
        if '->' in string:
            class_part = string.split('->')[0].strip()
            method_desc_part = string.split('->')[1].strip()
            if '(' in method_desc_part:
                method_part = method_desc_part.split('(')[0].strip()
                desc_part = \
                    '(' + (method_desc_part.split('(')[1])
                desc_part = desc_part.strip().replace(' ', '')
            else:
                method_part = method_desc_part.strip()
        else:
            class_part = string.strip()
        return [class_part, method_part, desc_part]
    
    def fn_get_class_method_desc_from_method(self, method):
        class_part = method.get_class_name().strip()
        method_part = method.get_name().strip()
        desc_part = method.get_descriptor().strip()
        return [class_part, method_part, desc_part]

    def fn_get_method_string_from_method(self, method):
        [class_part, method_part, desc_part] = \
            self.fn_get_class_method_desc_from_method(method)
        string = class_part + '->' + method_part + desc_part
        return string
    
    def fn_convert_signed_to_unsigned(self, negative_component_value):
        string_bin_value = format(abs(negative_component_value), '064b')
        inverted_bin_value = ''.join(
            '1' if x == '0' else '0' for x in string_bin_value)
        add_one = int(inverted_bin_value, 2) + int('1', 2)
        hex_value = (hex(add_one).replace('0x', '')).replace('L', '')
        return hex_value
    
    def fn_check_uuid_format(self, string):
        if type(string) is not str:
            return False
        # This is necessary.
        string = str(string).strip().replace("'",'').replace('"','')
        re_match = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}' \
                   + '-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        if (re.match(re_match, string)):
            return True
        else:
            return False
            
    def fn_add_uuid_string_to_output(self, key, uuid, class_name, src):
        if self.fn_check_uuid_format(uuid) == False:
            return False
        if src not in self.outputs:
            self.outputs[src] = {}
        if uuid not in self.outputs[src]:
            self.outputs[src][uuid] = {}
            self.outputs[src][uuid]['calling_methods'] = []
            self.outputs[src][uuid]['construction'] = []
        if key not in self.outputs[src][uuid]['construction']:
            self.outputs[src][uuid]['construction'].append(key)
        if class_name not in self.outputs[src][uuid]['calling_methods']:
            self.outputs[src][uuid]['calling_methods'].append(class_name)