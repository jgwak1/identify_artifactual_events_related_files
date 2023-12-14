# TODO: 
# 
# Write a script that reads in the 'single-technique custom adversary-profile <n> trials' elastic-search indices,
# then identifies the 'process-of-interest' (i.e. child-process of splunkd.exe) which corresponds to the powershell.exe
# that is spawned for the technique-execution
#
# Once identifeid the process-of-interest,
#  - Could look for 'Entities associated with Artifactual Events' 
#    (or could do an experiment of collecting logs for a single-technique-profile
#     with 'No command/Minimal-command(like Keyboard-Enter) and check its logs)
#  - Could look for Threads that perform artifactual events
# 
# Behavioral Events should be removing the artifactual events from the events from process-of-interest
# (i.e. For the Process-of-Interest, Behavioral-Events = All-Events - Artifactual Events  

from elasticsearch import Elasticsearch, helpers
from helper_funcs import *

import os
import pprint
import json

if __name__ == "__main__":

   # Confirmed that successfully run:
   #  t1003_001__credential-access__os_credential_dumping-_lsass_memory__35d92515122effdd73801c6ac3021da7__trial_<N> -- this one doesn't have trial-1 as due to setting up


   # ---------------------------------------------------------------------------------------------------------------
   SuccessfulExecuted__SingleTechniqueAdversary__TrialIndices__Set_1 = [
      # this one doesn't have trial_1 due to hassle in initially setting up
      "atomic__t1003_001__credential-access__os_credential_dumping-_lsass_memory__35d92515122effdd73801c6ac3021da7__trial_2",
      "atomic__t1003_001__credential-access__os_credential_dumping-_lsass_memory__35d92515122effdd73801c6ac3021da7__trial_3",
      "atomic__t1003_001__credential-access__os_credential_dumping-_lsass_memory__35d92515122effdd73801c6ac3021da7__trial_4",
      "atomic__t1003_001__credential-access__os_credential_dumping-_lsass_memory__35d92515122effdd73801c6ac3021da7__trial_5"
      ]


   SuccessfulExecuted__SingleTechniqueAdversary__TrialIndices__Set_2 = [

      "atomic__t1003__credential-access__os_credential_dumping__18f31c311ac208802e88ab8d5af8603e__trial_1",
      "atomic__t1003__credential-access__os_credential_dumping__18f31c311ac208802e88ab8d5af8603e__trial_2",
      "atomic__t1003__credential-access__os_credential_dumping__18f31c311ac208802e88ab8d5af8603e__trial_3",
      "atomic__t1003__credential-access__os_credential_dumping__18f31c311ac208802e88ab8d5af8603e__trial_4",
      "atomic__t1003__credential-access__os_credential_dumping__18f31c311ac208802e88ab8d5af8603e__trial_5",
      

   ]


   SuccessfulExecuted__TRIVIAL__SingleTechniqueAdversary__TrialIndices__Set_1 = [

      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_1",
      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_2",
      "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_3"

      ]


   ###############################################################################################################

   # 1. First get a map between trial_es_indices and ALL of its log-entries

   trial_es_indices_to_log_entries_dict = dict()

   trial_es_indices = SuccessfulExecuted__SingleTechniqueAdversary__TrialIndices__Set_1 + SuccessfulExecuted__SingleTechniqueAdversary__TrialIndices__Set_2

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

         #      make timestamps datetime-objects as done before and make sure it's sorted
         #      need to also deal with descendent processes (one example is "rundll32.exe")
         #      including the descendent process's artifacts.
         #           

         # -----------------------------------------------------------                     
         # NOTE THAT NOT NECESSARILY IN SORTED ORDER in terms of timestamp 
         
         # unsorted_elements, unsorted_element_indices = find_unsorted_elements_and_indices( timestamp_array )

               # # investigated reason: comes from different process-thread
               # [ {"ProcessID": x['_source']['ProcessID'], "ThreadID": x['_source']['ThreadID'], "@timestamp": x['_source']['@timestamp']} \
               # for x in process_of_interest_and_its_descendents_log_entries[ 449 : 450 + 1 ] ]

               # So it is might be just better (may not hurt) to first sort by timestamp, 
               # for explanation point of view (since any way will mask out from the “input-graph” 
               #  – in case input-data is a pure sequence of log-entires mingled across different threads, need to rethink )
               
               # DONE: First figure out if log-entries are at least sorted within the same Process-Thread
               #       --> Confirmed that even within the same process-thread, not sorted in order
               #           might have to do something with internal streaming (in batches?)
         
               # processThread_to_logentries_dict = group_log_entries_by_processThreads( process_of_interest_and_its_descendents_log_entries )
               # check_whether_log_entries_sorted_within_same_ProcessThread(group_log_entries_by_processThreads)

          # DONE: Sort by timestamp here -- confirmed it works

         process_of_interest_and_its_descendents_log_entries_SORTED = sorted( process_of_interest_and_its_descendents_log_entries, key= lambda item: item['_source']['@timestamp'] )

            # timestamp_array = [ x['_source']['@timestamp'] for x in process_of_interest_and_its_descendents_log_entries_SORTED ]
            # find_unsorted_elements_and_indices(timestamp_array)
         






         # 3. Identify artifact events (e.g. by artifact-entities or
         #                                      artifact-threads)
         
         # DONE: Implement "group_log_entries_by_processThreads()"
         processThread_to_logentries_dict = group_log_entries_by_processThreads( process_of_interest_and_its_descendents_log_entries_SORTED )

         # TODO: Implement "group_log_entries_by_Entity()"
         #       (refer to "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_1__Sequential_pattern_mining/sequential_pattern_mining__Entity_Level__DoubleBatch__super_batch_outputs.pyn")
         #       And check if certain threads are responsible for initialization-entities (e.g. dll )

         # import json
         # with open(
         #    os.path.join("/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events",
         #    f'processThread_to_logentries_dict__{trial_es_index}__dict.json'), 'w') as fp:
         #    json.dump(processThread_to_logentries_dict, fp)

         # print()

         # JY @ 2023-11-13 -- For ProcessProvider Entities, the entity can be 'Process' or 'Process-Thread', for robustness may have to consider "timestamp"
         process_of_interest_and_its_descendents_log_entries_SORTED_with_EntityInfo = \
            get_log_entries_with_entity_info( process_of_interest_and_its_descendents_log_entries_SORTED )



         # JY @ 2023-11-13 -- Read in the "artifactual_entities_dlls" obtained based on the "minimal-impact custom-technique" 
         #                    (i.e., "joonyoung_no_command_single_technique_profile_for_artifactual_event_identification_trial_1")
         with open("/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events/artifactual_events_summary/artifactual_entities_dlls.json","r") as file:
               artifactual_entities_dll_fpaths = json.load(file)      
         artifactual_entities_dll_fnames = [ x.split("\\")[-1] for x in artifactual_entities_dll_fpaths ]     # 148
         artifactual_entities_dll_fnames_set = set( artifactual_entities_dll_fnames ) # 74  --- halved b/c each entity is associaed with a imageload & imageunload event



         # JY @ 2023-11-13: 
         #     What exactly is the "FileObject" of ETW log-entries? 
         #     Why are there 'one-to-many' relation from FileName -> FileObjects ?

         # for log_entry in process_of_interest_and_its_descendents_log_entries_SORTED_with_EntityInfo:
               
         #       entity_name = log_entry['PROVIDER_SPECIFIC_ENTITY'].split("\\")[-1] # to match for cases where there are "\\"
               
         #       taskname = log_entry['_source']['EventName']

         #       x = log_entry['_source']['XmlEventData'].get('FormattedMessage')
         #       if x != None:
         #          entity_name = x.split("\\")[-1]


         #       if (entity_name in artifactual_entities_dll_fnames_set):
         #          # if (taskname.lower() in {"imageload", "imageunload"}) :
         #             process_of_interest_and_its_descendents_log_entries_SORTED_with_EntityInfo.remove( log_entry )
         





         summarized_process_of_interest_and_its_descendents_log_entries_SORTED = summarize_log_entires_by_entity_and_key_info( process_of_interest_and_its_descendents_log_entries_SORTED )

         trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED[trial_es_index] = {"event_summaries": summarized_process_of_interest_and_its_descendents_log_entries_SORTED,
                                                                                                                      "process_of_interest_and_its_descendents_dict": process_of_interest_and_its_descendents_dict,
                                                                                                                      "splunkd_and_descendent_pids_dict": splunkd_and_descendent_pids_dict
                                                                                                                      }

         # Group log_entries by entities, many are associated with None

         entity_to_logentires_dict = group_log_entries_by_entities( process_of_interest_and_its_descendents_log_entries_SORTED_with_EntityInfo )

         # import json
         # with open(
         #    os.path.join("/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events",
         #    f'entity_to_log_entries__{trial_es_index}__dict.json'), 'w') as fp:
         #    json.dump(entity_to_logentires_dict, fp)

         # print()


   # For each key-value pair of "trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED",
   # write out a txt file with 'key' as fname, and 'value' as its content
   print()
   trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED


   with open("/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events/caldera_ability_id__MitreTechniqueID__map_dict.json","r") as file:
      caldera_ability_id__MitreTechniqueID__map_dict = json.load(file)


   index_key_events_summary_dirpath = "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_0__Identify_Behavioral_Events/index_key_event_summaries"   
   if not os.path.exists(index_key_events_summary_dirpath):
      os.makedirs( index_key_events_summary_dirpath )


   for trial_es_index, nested_dict in trial_es_index__to__summarized_process_of_interest_and_its_descendents_log_entries_SORTED.items():

      trial_es_index__single_technique_id = trial_es_index.split("__")[-2]

      trial_es_index__single_technique_id__info_dict = caldera_ability_id__MitreTechniqueID__map_dict[trial_es_index__single_technique_id]

      event_summaries = nested_dict["event_summaries"]
      process_of_interest_and_its_descendents_dict = nested_dict["process_of_interest_and_its_descendents_dict"]
      splunkd_and_descendent_pids_dict = nested_dict["splunkd_and_descendent_pids_dict"]
      for pid in splunkd_and_descendent_pids_dict: # for better readability 
         splunkd_and_descendent_pids_dict[pid]['Timestamp'] = str( splunkd_and_descendent_pids_dict[pid]['Timestamp'] )

      fpath = os.path.join( index_key_events_summary_dirpath ,
                               f"{trial_es_index}__processes_of_interest_event_summary.txt")

      with open( fpath , "w") as fp:
      
         fp.write(f"[  {trial_es_index}  ]\n-->  process-of-interest and its descendent processes (below)  events-summary (sorted by timestamp) ]\n\n")
         fp.write(f"\n{pprint.pformat(process_of_interest_and_its_descendents_dict)}\n")
         fp.write("------------------------------------------------------------------\n")
         fp.write("< splunkd_and_descendent_pids_dict (for reference) -- single-technique process corresponds to the last spawned child of splunkd.exe >:\n\n")
         fp.write(f"\n{pprint.pformat(splunkd_and_descendent_pids_dict)}\n")
         fp.write("------------------------------------------------------------------\n")
         fp.write("< single-technique information (from the single-technique-profile) >:\n\n")         
         fp.write(f"\n{pprint.pformat(trial_es_index__single_technique_id__info_dict)}\n")
         fp.write("\n\n\n")
         fp.write("================================================================================\n")
         for event_summary in event_summaries:
            fp.write(f"{event_summary}\n")
            
      


         
