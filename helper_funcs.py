''' source : /data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_1__Sequential_pattern_mining/sequential_pattern_mining__DoubleBatch__super_batch_outputs.py'''

from datetime import datetime

from collections import defaultdict


def get_splunkd_and_descendent_pids( es_index__all_log_entries : list ) -> dict:

         # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
         #                   Need to write code that first figures out the
         #                   dependencies (root == splunkd process and process-tree)
         #     First write a loop for identifying that.


         splunkd_and_descendent_pids = dict()
         first_splunkd_entry_found = False

         for i, log_entry in enumerate(es_index__all_log_entries):
            logentry_TaskName = log_entry.get('_source', {}).get('EventName')
            logentry_ProcessID = log_entry.get('_source', {}).get('ProcessID')
            logentry_ThreadID = log_entry.get('_source', {}).get('ThreadID')
            logentry_ProcessName = log_entry.get('_source', {}).get('ProcessName')
            logentry_ProviderName = log_entry.get('_source', {}).get('ProviderName')
            logentry_ProviderGuid = log_entry.get('_source', {}).get('ProviderGuid')
            logentry_XmlEventData = log_entry.get('_source', {}).get('XmlEventData')


            logentry_timestamp_raw_str = log_entry.get('_source', {}).get('@timestamp')
            # convert logentry_timestamp raw-string (e.g. '2023-11-08T17:14:37.327690900Z') into a datetime object

            decimal_places = 6 # precision to allow -- datetime.strptime can only handle upto 6
            precision_dot_pos = logentry_timestamp_raw_str.find('.')
            if precision_dot_pos != -1: truncated_logentry_timestamp_raw_str = logentry_timestamp_raw_str[:precision_dot_pos + 1 + decimal_places]
            else: truncated_logentry_timestamp_raw_str = logentry_timestamp_raw_str  # No dot found           

            if truncated_logentry_timestamp_raw_str[-1].lower() == 'z': # drop the trailing Z if there is
                truncated_logentry_timestamp_raw_str = truncated_logentry_timestamp_raw_str[:-1]


            logentry_timestamp = datetime.strptime(truncated_logentry_timestamp_raw_str,
                                                   '%Y-%m-%dT%H:%M:%S.%f')


            # ==============================================================================================
            # 1. Get the PID of "splunkd.exe"
            #    Could utilize the 'json' file in "caldera/etw/tmp", 
            #    but there wre incidents where it is incorrect.
            #    So just capture the first entry with ProcessName of "splunkd"
            #    and get the PID

            if ("splunkd" in logentry_ProcessName) and (first_splunkd_entry_found == False):
               splunkd_and_descendent_pids[logentry_ProcessID] = {"ProcessName": logentry_ProcessName,
                                                                  "ParentProcessID" : "no-need-to-collect",
                                                                  "FormattedMessage": "no-need-to-collect",
                                                                  "Timestamp": logentry_timestamp,
                                                                  }
               first_splunkd_entry_found = True
            # ==============================================================================================

            # 2. Record the descendent processes of splunkd
            if ("ProcessStart" in logentry_TaskName) and (first_splunkd_entry_found == True):
               
               ProcessStart_Event_ParentProcessID = int(logentry_XmlEventData['ParentProcessID'].replace( "," , "" ))
               ProcessStart_Event_ChildProcessID = int(logentry_XmlEventData['ProcessID'].replace( "," , "" ))
               ProcessStart_Event_FormattedMessage = logentry_XmlEventData['FormattedMessage']

               if ProcessStart_Event_ParentProcessID in splunkd_and_descendent_pids:
                  splunkd_and_descendent_pids[ ProcessStart_Event_ChildProcessID ] = {"ProcessName": "N/A",
                                                                                      "ParentProcessID" : ProcessStart_Event_ParentProcessID,
                                                                                      "FormattedMessage": ProcessStart_Event_FormattedMessage,
                                                                                      "Timestamp": logentry_timestamp,
                                                                                      }
            # ==============================================================================================
            # 3. Try to get the ProcessName of descendent-processes of splunkd 
            #    (empirically, could get 'conhost' but others hard to get -- values are N/A )

            if (logentry_ProcessID in splunkd_and_descendent_pids) and (splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] == "N/A"):
               splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] = logentry_ProcessName
         
         
         return splunkd_and_descendent_pids




def get_log_entries_of_process_of_interest_and_descendents( es_index__all_log_entries : list,
                                                            process_of_interest_and_its_descendents_dict : dict ) -> list:

         # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
         #                   Need to write code that first figures out the
         #                   dependencies (root == splunkd process and process-tree)
         #     First write a loop for identifying that.

         process_of_interest_and_descentdents_log_entries = []

         for i, log_entry in enumerate(es_index__all_log_entries):
            logentry_ProcessID = log_entry.get('_source', {}).get('ProcessID')
            logentry_TaskName = log_entry.get('_source', {}).get('EventName')

            if logentry_ProcessID in process_of_interest_and_its_descendents_dict:
                  # ==============================================================================================
                  # tasknames to skip
                  # -- based on : /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py
                  if logentry_TaskName.lower() in ["operationend", "namedelete"]: 
                     continue
                  # ==============================================================================================

                  # Also replace log-entry's timestamp attribute into datetime-object for later conveninces
                  logentry_timestamp_raw_str = log_entry.get('_source', {}).get('@timestamp')
                  # convert logentry_timestamp raw-string (e.g. '2023-11-08T17:14:37.327690900Z') into a datetime object

                  decimal_places = 6 # precision to allow -- datetime.strptime can only handle upto 6
                  precision_dot_pos = logentry_timestamp_raw_str.find('.')
                  if precision_dot_pos != -1: truncated_logentry_timestamp_raw_str = logentry_timestamp_raw_str[:precision_dot_pos + 1 + decimal_places]
                  else: truncated_logentry_timestamp_raw_str = logentry_timestamp_raw_str  # No dot found           

                  if truncated_logentry_timestamp_raw_str[-1].lower() == 'z': # drop the trailing Z if there is
                     truncated_logentry_timestamp_raw_str = truncated_logentry_timestamp_raw_str[:-1]


                  logentry_timestamp_datetime_object = datetime.strptime(truncated_logentry_timestamp_raw_str,
                                                                         '%Y-%m-%dT%H:%M:%S.%f')

                  log_entry['_source']['@timestamp'] = logentry_timestamp_datetime_object

                  # ==============================================================================================

                  process_of_interest_and_descentdents_log_entries.append(log_entry)


         return process_of_interest_and_descentdents_log_entries




def find_unsorted_elements_and_indices(lst, sorted_order = "ascending"):


      def compare(x1, x2):
         if sorted_order == "ascending": return x1 <= x2
         elif sorted_order == "descending": return x2 >= x1
         else: raise ValueError("sorted-order choices : ['ascending', 'descending']")

      unsorted_elements = []
      unsorted_element_indices = []
      for i in range(len(lst) - 1):
         if not compare(lst[i], lst[i + 1]) :
               unsorted_elements.append((lst[i], lst[i + 1]))
               unsorted_element_indices.append([i, i+1])
      return unsorted_elements, unsorted_element_indices


def group_log_entries_by_processThreads(log_entries : list) -> dict:
    
    # JY @ 2023-11-09: Correcntess of this function seems OK
    #                  Cross-checked with Elastic-search Index 

    processThread_to_logentries_dict = dict()

    # first group log-entries by process
    # then group log-entries by thread


    for log_entry in log_entries:
        
        log_entry_pid = log_entry['_source']['ProcessID']
        log_entry_tid = log_entry['_source']['ThreadID']

        log_entry['_source']['@timestamp'] = str(log_entry['_source']['@timestamp']) # for pickling

        if log_entry_pid in processThread_to_logentries_dict: # if log-entry's pid exists as a key

           if log_entry_tid in processThread_to_logentries_dict[log_entry_pid]:
               # under this process, there exists a key for the thread,
               # so just append it 

               processThread_to_logentries_dict[log_entry_pid][log_entry_tid].append(log_entry)

           else:
               # under this process, first event for this process-thread
               # so create space for it, and append the first event
               processThread_to_logentries_dict[log_entry_pid][log_entry_tid] = list()
               processThread_to_logentries_dict[log_entry_pid][log_entry_tid].append(log_entry)

        else:
            # if log-entry's pid key is not populated yet,
            # obviously there is no corresponding space for the process-thread
            # so create the space and append the first log-entry for that process-thread             
            processThread_to_logentries_dict[log_entry_pid] = dict()
            processThread_to_logentries_dict[log_entry_pid][log_entry_tid] = list()
            processThread_to_logentries_dict[log_entry_pid][log_entry_tid].append( log_entry )

    # returns dict of dict 
    return processThread_to_logentries_dict




def check_whether_log_entries_sorted_within_same_ProcessThread( processThread_to_logentries_dict : dict ):
    
      # following is for checking whether log-entries are at least sorted within the same process-thread
      # already observed a case where log-entries are not sorted by within the same process
      for pid in processThread_to_logentries_dict:
         for tid in processThread_to_logentries_dict[pid]:
            pid_tid_logentries = processThread_to_logentries_dict[pid][tid]
            pid_tid_timestamp_array = [ x['_source']['@timestamp'] for x in pid_tid_logentries ]
            unsorted_elements, unsorted_element_indices = find_unsorted_elements_and_indices( pid_tid_timestamp_array )
            print()

            # [ {"ProcessID": x['_source']['ProcessID'], 
            #    "ThreadID": x['_source']['ThreadID'], 
            #    "EventName": x['_source']['EventName'], 
            #    "XmlEventData": x['_source']['XmlEventData'], 

            #    "@timestamp": x['_source']['@timestamp']} \
            # for x in pid_tid_logentries[ 25 : 26 + 1 ] ]    






def get_log_entries_with_entity_info( log_entries : list ) -> list:

   ''' TODO / TOTHINK '''
   # JY @ 2023-11-09: 
   #     QUESTION -- WHICH ENTITY SHOULD I ASSOCIATE A PROCESS-PROVIDER EVENT TO?
   #     
   #     For PROCESS-PROVIDER events, I guess entites can be process/thread 
   #     as in CG, a PROCESS-PROVIDER event happens between the 
   #     log-entry thread-node and process-node/thread-node
   # 
   #     perhaps the description for the entity-(process/thread)-node can be the
   #     relation with the log-entry thread-node (e.g. parent/child process / sibling-thread / itself, etc)
   #     -- for details, might need to refer to the FirstStep.py


   FILE_PROVIDER = "EDD08927-9CC4-4E65-B970-C2560FB5C289"
   NETWORK_PROVIDER = "7DD42A49-5329-4832-8DFD-43D979153A88"
   PROCESS_PROVIDER = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"
   REGISTRY_PROVIDER = "70EB4F03-C1DE-4F73-A051-33D13D5413BD"


   ''' JY @ 2023-11-1: 
            Should the entity be same as UID if we are to utilize CG for explanation?
   
   '''

   log_entries_with_entity_info = []

   # For following,
   # refer to: /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py
   fileobject_to_filename_mapping = dict()
   keyobject_to_relativename_mapping = dict()
   


   for log_entry in log_entries:


      logentry_ProviderGuid = log_entry.get('_source', {}).get('ProviderGuid')
      logentry_TaskName = log_entry.get('_source', {}).get('EventName')
      logentry_ProcessID = log_entry.get('_source', {}).get('ProcessID')
      logentry_ThreadID = log_entry.get('_source', {}).get('ThreadID')
      # logentry_XmlEventData = log_entry.get('_source', {}).get('XmlEventData')

      # log_entry['GENERAL_ENTITY'] = f"{logentry_ProcessID}__{logentry_ThreadID}" # this doesn't really make sense 
                                                                                    # to use within sequence

      if logentry_TaskName.lower() in ["operationend", "namedelete"]: 
         continue


      #=============================================================================================================
      if logentry_ProviderGuid == FILE_PROVIDER.lower():
         # Entity associated with a File-Event?
         # --> Probably the 'File'            
         # ----> 'FileName' or 'FileObject', etc. depending on Event (need to resolve 'mapping')
         # ----> also, keep track of process & thread that carried out the file-event
         



         logentry_FileName = log_entry.get('_source', {}).get('XmlEventData').get('FileName') 
         logentry_FileObject = log_entry.get('_source', {}).get('XmlEventData').get('FileObject') 


         if logentry_TaskName.lower() in {"create", "createnewfile"}:
            # JY: 'create' and 'createnewfile' provides both 'logentry_FileObject' and 'logentry_FileName'
            fileobject_to_filename_mapping[logentry_FileObject] = str(logentry_FileName)
            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{str(logentry_FileName)}"


         elif logentry_TaskName.lower() in {"close"}:
            # JY: "close" appear to provide only 'logentry_FileObject'
            logentry_FileName = fileobject_to_filename_mapping.get(logentry_FileObject, "None")
            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{logentry_FileName}"

         else: # all other tasknames
            # JY: ALL OTHER Opcodes appear to provide only 'logentry_FileObject'
            logentry_FileName = fileobject_to_filename_mapping.get(logentry_FileObject, "None")
            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{logentry_FileName}"



      #=============================================================================================================
      if logentry_ProviderGuid == REGISTRY_PROVIDER.lower():
         # Entity associated with a Registry-Event?
         # --> Probably the 'Registry-Key'            
         # ----> 'RelativeName' or 'KeyObject', etc. depending on Event (need to resolve 'mapping')
         # ----> also, keep track of process & thread that carried out the file-event


         logentry_OpcodeName = log_entry.get('_source', {}).get('OpcodeName')

         logentry_KeyObject = log_entry.get('_source', {}).get('XmlEventData').get('KeyObject') 
         logentry_RelativeName = log_entry.get('_source', {}).get('XmlEventData').get('RelativeName') 

         logentry_KeyName = log_entry.get('_source', {}).get('XmlEventData').get('KeyName') # ?

         #if logentry_TaskName in {'EventID(1)','EventID(2)'}:---> option 1
         if logentry_OpcodeName in {"CreatKey","OpenKey"}: #-----> option2 
            # JY: 'CreateKey' and 'OpenKey' provides both 'logentry_KeyObject' and 'logentry_RelativeName'

            keyobject_to_relativename_mapping[logentry_KeyObject] = str(logentry_RelativeName)

            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{str(logentry_RelativeName)}"  # add to entity

         #elif logentry_TaskName == 'EventID(13)' --->option1 
         elif logentry_OpcodeName == "CloseKey": #--->option2

            # JY: "CloseKey" appear to provide only 'logentry_KeyObject'

            logentry_RelativeName = keyobject_to_relativename_mapping.get(logentry_KeyObject, "None")

            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{logentry_RelativeName}"

         else: # ALL OTHER Opcodes  
            # JY: ALL OTHER Opcodes appear to provide only 'logentry_KeyObject'

            logentry_RelativeName = keyobject_to_relativename_mapping.get(logentry_KeyObject, "None")

            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{logentry_RelativeName}"

      #=============================================================================================================

      if logentry_ProviderGuid == NETWORK_PROVIDER.lower():
         # Entity associated with a Network-Event?
         # --> Probably the 'IP-address' that 'this-machine' communicated with            
         # ----> 'daddr' depending on Event 
         # ----> also, keep track of process & thread that carried out the file-event

         logentry_destaddr = log_entry.get('_source', {}).get('XmlEventData').get('daddr') 

         log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_destaddr}"


      #=============================================================================================================

      if logentry_ProviderGuid == PROCESS_PROVIDER.lower():
         # Entity associated with a Process-Event?
         # --> Process and Thread that took action.

         log_entry['PROVIDER_SPECIFIC_ENTITY'] = "None"

         # Perhaps imagename? -- I think this mostly happens when imageload-and-unload events -- so don't use it.
         # logentry_ImageName = log_entry.get('_source_XmlEventData_ImageName', 'None')

         # if logentry_ImageName != "None":
         #    print()
         pass

      #=============================================================================================================
      log_entries_with_entity_info.append(log_entry)


   

   # [ f"{x['_source_EventName']}__{x['PROVIDER_SPECIFIC_ENTITY']}" for x in log_entries_with_entity_info ] 

   # [ {"ProcessID": x['_source_ProcessID'],
   #    "ThreadID": x['_source_ThreadID'],
   #    "TaskName": x['_source_EventName'],
   #    "logentry_OpcodeName": x['_source_OpcodeName'],
   #    "PROVIDER_SPECIFIC_ENTITY": x['PROVIDER_SPECIFIC_ENTITY']} 
   # for x in log_entries_with_entity_info ] 
      
      # x['_source_EventName']}__{x['PROVIDER_SPECIFIC_ENTITY']}" for x in log_entries_with_entity_info ] 

   return log_entries_with_entity_info



def summarize_log_entires_by_entity_and_key_info( log_entries__with_EntityInfo ):

   summarized_log_entries = list()

   for log_entry in log_entries__with_EntityInfo:
       

      log_entry_entity = log_entry['PROVIDER_SPECIFIC_ENTITY']

      log_entry_ProviderGuid = log_entry['_source']['ProviderGuid']  
      log_entry_pid = log_entry['_source']['ProcessID']
      log_entry_tid = log_entry['_source']['ThreadID']
      log_entry_timestamp = log_entry['_source']['@timestamp']


      log_entry_TaskName = log_entry['_source']['EventName']
      log_entry_OpcodeName = log_entry['_source']['OpcodeName']

      logentry_XmlEventData_FormattedMessage = log_entry['_source']['XmlEventData'].get('FormattedMessage')

      summarized_log_entries.append( {
               # ordered as following for easier readability
               "Timestamp": str(log_entry_timestamp),
               "ProcessID": log_entry_pid,
               "ThreadID": log_entry_tid,
               "PROVIDER_SPECIFIC_ENTITY": log_entry_entity,             
               "TaskName": log_entry_TaskName,
               "OpcodeName": log_entry_OpcodeName,
               "FormattedMessage": logentry_XmlEventData_FormattedMessage, # ChatGPT understand the FormattedMessage?
               # "ProviderGuid": log_entry_ProviderGuid, # May not be necessary, as already have Taskname ; and makes the string too long
            } )

   return summarized_log_entries


def group_log_entries_by_entities( log_entries__with_EntityInfo : list):
    
   entity_to_logentries_dict = dict()

   for log_entry in log_entries__with_EntityInfo:
       

      log_entry_entity = log_entry['PROVIDER_SPECIFIC_ENTITY']

      log_entry_ProviderGuid = log_entry['_source']['ProviderGuid']  
      log_entry_pid = log_entry['_source']['ProcessID']
      log_entry_tid = log_entry['_source']['ThreadID']
      log_entry_timestamp = log_entry['_source']['@timestamp']


      log_entry_TaskName = log_entry['_source']['EventName']
      log_entry_OpcodeName = log_entry['_source']['OpcodeName']


      if log_entry_entity in entity_to_logentries_dict:
         
            entity_to_logentries_dict[log_entry_entity].append( {
               
               "ProcessID": log_entry_pid,
               "ThreadID": log_entry_tid,
               "Timestamp": str(log_entry_timestamp),
               "TaskName": log_entry_TaskName,
               "OpcodeName": log_entry_OpcodeName,
               # "ProviderGuid": log_entry_ProviderGuid,
               "PROVIDER_SPECIFIC_ENTITY": log_entry_entity,             
               }
            )

      else:
        
         entity_to_logentries_dict[log_entry_entity] = list()
         entity_to_logentries_dict[log_entry_entity].append( {
               
               "ProcessID": log_entry_pid,
               "ThreadID": log_entry_tid,
               "Timestamp": str(log_entry_timestamp),
               "TaskName": log_entry_TaskName,
               "OpcodeName": log_entry_OpcodeName,
               # "ProviderGuid": log_entry_ProviderGuid,
               "PROVIDER_SPECIFIC_ENTITY": log_entry_entity,             
               }
            )        


   return entity_to_logentries_dict







