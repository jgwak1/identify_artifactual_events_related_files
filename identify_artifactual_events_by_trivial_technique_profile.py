
from elasticsearch import Elasticsearch, helpers
from helper_funcs import *

import os
import pprint
import json
import re 

if __name__ == "__main__":


   SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1 = [

      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_1",
      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_2",
      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_3"

      ]
   trial_es_indices_to_log_entries_dict = dict()

   trial_es_indices = SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1

   skipped_indices = []

   for trial_es_index in trial_es_indices:

      try:
         # Read in all log entries of current es-index.
         es = Elasticsearch(['http://ocelot.cs.binghamton.edu:9200'],timeout = 300)   
         es.indices.put_settings(index = trial_es_index, body={'index':{'max_result_window':99999999}})
         result = es.search(index = trial_es_index, 
                           size = 99999999)
         es_index__all_log_entries = result['hits']['hits']    # list of dicts

         trial_es_indices_to_log_entries_dict[trial_es_index] = es_index__all_log_entries

      except:
         skipped_indices.append(trial_es_index)
         print(f"\n{len(skipped_indices)}:  {trial_es_index}  is skipped as Elasticsearch doesn't contain it\n", flush = True)


   # 2. Second, get the log-entries of the 
   #    'process-of-interest' (actual single-technique from the single-technique-profile) 

   
   trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED = dict()


   for trial_es_index, all_log_entries in trial_es_indices_to_log_entries_dict.items():

         print(f"started for {trial_es_index}")

         splunkd_and_descendent_pids_dict = get_splunkd_and_descendent_pids( all_log_entries )

         # 2-1:
         # process-of-interest (actual single-technique from the single-technique-profile) 
         # should be the last spawned process (normally 2nd) among child-processes of splunkd.exe
         splunkd_pid = None
         for pid in splunkd_and_descendent_pids_dict:
            if splunkd_and_descendent_pids_dict[pid]['ProcessName'] == 'splunkd':
               splunkd_pid = pid
               break
         children_of_splunkd_dict = dict()
         for pid in splunkd_and_descendent_pids_dict:
            if splunkd_and_descendent_pids_dict[pid]['ParentProcessID'] == splunkd_pid:
               children_of_splunkd_dict[pid] = splunkd_and_descendent_pids_dict[pid]
         
         pids_sorted_by_timestamp = sorted(children_of_splunkd_dict.items(), 
                                          key=lambda item: item[1]['Timestamp'])

         process_of_interest_pid = pids_sorted_by_timestamp[-1][0] # order appears to match results in
                                                                  # "splunkd_tree_artificial_processes_identification.txt"

         
         process_of_interest_and_its_descendents_dict = dict()
         
         process_of_interest_and_its_descendents_dict[process_of_interest_pid] = splunkd_and_descendent_pids_dict[process_of_interest_pid]
         process_of_interest_and_descendents_pids = [ process_of_interest_pid ]
         
         for pid in splunkd_and_descendent_pids_dict:
            if splunkd_and_descendent_pids_dict[pid]['ParentProcessID'] in process_of_interest_and_descendents_pids:
               process_of_interest_and_descendents_pids.append( pid )
               process_of_interest_and_its_descendents_dict[pid] = splunkd_and_descendent_pids_dict[pid]


         # 2-2: Get the log-entries of the process-of-interest (and its descendents, if any)

         process_of_interest_and_its_descendents_log_entries = \
            get_log_entries_of_process_of_interest_and_descendents( all_log_entries, 
                                                                    process_of_interest_and_its_descendents_dict )


         # 2-3: Log-entries are not sorted by timestamps by default.
         #      They are only sorted within the thread (check this)
         #      So explicitly sort it here

         process_of_interest_and_its_descendents_log_entries_SORTED = sorted( process_of_interest_and_its_descendents_log_entries, key= lambda item: item['_source']['@timestamp'] )

            # timestamp_array = [ x['_source']['@timestamp'] for x in process_of_interest_and_its_descendents_log_entries_SORTED ]
            # find_unsorted_elements_and_indices(timestamp_array)
         


         # 3. Identify artifact events (e.g. by artifact-entities or
         #                                      artifact-threads)
         
         processThread_to_logentries_dict = group_log_entries_by_processThreads( process_of_interest_and_its_descendents_log_entries_SORTED )


         process_of_interest_and_its_descendents_log_entries_SORTED_with_EntityInfo = \
            get_log_entries_with_entity_info( process_of_interest_and_its_descendents_log_entries_SORTED )


         summarized_process_of_interest_and_its_descendents_log_entries_SORTED = summarize_log_entires_by_entity_and_key_info( process_of_interest_and_its_descendents_log_entries_SORTED )

         trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED[trial_es_index] = {"event_summaries": summarized_process_of_interest_and_its_descendents_log_entries_SORTED,
                                                                                                                      "process_of_interest_and_its_descendents_dict": process_of_interest_and_its_descendents_dict,
                                                                                                                      "splunkd_and_descendent_pids_dict": splunkd_and_descendent_pids_dict
                                                                                                                      }

         artifactual_events_summary_dirpath = "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events/artifactual_events_summary"   
         if not os.path.exists(artifactual_events_summary_dirpath):
            os.makedirs( artifactual_events_summary_dirpath )


         for trial_es_index, nested_dict in trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED.items():


               event_summaries = nested_dict["event_summaries"]
               process_of_interest_and_its_descendents_dict = nested_dict["process_of_interest_and_its_descendents_dict"]
               splunkd_and_descendent_pids_dict = nested_dict["splunkd_and_descendent_pids_dict"]
               for pid in splunkd_and_descendent_pids_dict: # for better readability 
                  splunkd_and_descendent_pids_dict[pid]['Timestamp'] = str( splunkd_and_descendent_pids_dict[pid]['Timestamp'] )


               fpath = os.path.join( artifactual_events_summary_dirpath ,
                                       f"{trial_es_index}__processes_of_interest_event_summary.txt")



               # with open( fpath , "w") as fp:
               
               #    fp.write(f"[  {trial_es_index}  ]\n-->  process-of-interest and its descendent processes (below)  events-summary (sorted by timestamp) / #events: {len(event_summaries)}\n\n")
               #    fp.write(f"\n{pprint.pformat(process_of_interest_and_its_descendents_dict)}\n")
               #    fp.write("------------------------------------------------------------------\n")
               #    fp.write("< splunkd_and_descendent_pids_dict (for reference) -- single-technique process corresponds to the last spawned child of splunkd.exe >:\n\n")
               #    fp.write(f"\n{pprint.pformat(splunkd_and_descendent_pids_dict)}\n")
               #    fp.write("\n\n\n")
               #    fp.write("================================================================================\n")
               #    for event_summary in event_summaries:
               #       fp.write(f"{event_summary}\n")            

   print()


   # JY @ 2023-11-12
   # For log-entries, get the Ordered-set of tuple of (<TaskName, 'Opcode', <"Templated" Formatted Message i.e., template the prcoess-id and thread-id, and specific timestamp-info> ) 
   # then find the non-intersectting log-entries                     
  
   x = dict()
   x_additional = dict()

   for es_index, nested_dict in trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED.items():
      
      x[es_index] = list()
      x_additional[es_index] = list()

      for event_summary in nested_dict["event_summaries"]:

         event_ProcessID = event_summary['ProcessID']
         event_ThreadID = event_summary['ThreadID']
         event_FormattedMessage = event_summary['FormattedMessage'].replace(',','') # get rid of ',' for cases like '7,588' --> '7588'

         Processed__event_FormattedMessage = event_FormattedMessage.replace(str(event_ProcessID), '<ProcessID>').replace(str(event_ThreadID), '<ThreadID>')

         Processed__event_FormattedMessage = re.sub(r'\d', '', Processed__event_FormattedMessage) # drop all digits

         # x[es_index].append( (event_summary['TaskName'], event_summary['OpcodeName'], Processed__event_FormattedMessage) )

         x[es_index].append( Processed__event_FormattedMessage )

         x_additional[es_index].append( { "ProcessID": event_ProcessID,
                                          "ThreadID": event_ThreadID,
                                          "FormattedMessage": Processed__event_FormattedMessage,
                                          "TaskName": event_summary['TaskName'],
                                          "OpcodeName": event_summary['OpcodeName'],
                                       } )

   # -- now figure out the 
   print()

   x0= x[ SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1[0] ] 
   x0_with_dll = [y for y in x0 if 'dll' in y]
   x0_without_dll = [y for y in x0 if 'dll' not in y]

   x0_with_dll_set = set(x0_with_dll)
   x0_without_dll_set = set(x0_without_dll)

   x1= x[ SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1[1] ] 
   x1_with_dll = [y for y in x1 if 'dll' in y]
   x1_without_dll = [y for y in x1 if 'dll' not in y]
   x1_with_dll_set = set(x1_with_dll)
   x1_without_dll_set = set(x1_without_dll)

   x2= x[ SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1[2] ]       
   x2_with_dll = [y for y in x2 if 'dll' in y]
   x2_without_dll = [y for y in x2 if 'dll' not in y]
   x2_with_dll_set = set(x2_with_dll)
   x2_without_dll_set = set(x2_without_dll)


   # Get rid of the events, that load and unload the following files.

   x1_with_dll
   x1_with_dll_set
   x1_without_dll
   x1_without_dll_set
   x1_additional = x_additional[ SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1[1] ]

   artifactual_entities_dlls = [ message.split(" ")[-2][:-1] for message in x1_with_dll_set ]

   # JY : extract all dll files now




   # fpath = os.path.join( artifactual_events_summary_dirpath ,
   #                         # f"processed_formatted_messages_log_entry_SET__without_dll.txt")
   #                         f"processed_formatted_messages_log_entries__with_additional_info.txt")

   # with open( fpath , "w") as fp:
   
   #    for log_entry in x1_additional:
   #       fp.write(f"{log_entry}\n")              



   import json
   with open(
      os.path.join(artifactual_events_summary_dirpath, 'artifactual_entities_dlls.json'), 'w') as fp:
      json.dump(artifactual_entities_dlls, fp)   