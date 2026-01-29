# 🔹 1. Standard Library Imports (alphabetical)

import time

  

# 🔹 2. Third-Party Library Imports (alphabetical)

from colorama import Fore, init

from openai import OpenAI

from azure.identity import DefaultAzureCredential

from azure.monitor.query import LogsQueryClient

  

# 🔹 3. Internal/Local Imports (grouped by layer or concern)

import utilities

import queries.log_analytics_queries as queries

import models.models as models

from secrets_ import LOG_ANALYTICS_WORKSPACE_ID, API_KEY

  

# 🔹 4. Context (prompts, prompt builder)

import context.prompts as prompts

from context.prompts import SYSTEM_PROMPT_THREAT_HUNT

from context.prompt_builder import build_threat_hunt_prompt

  

# 🔹 5. Protocols (tools, logic)

from protocols.function_tools import tools

import protocols.hunt_protocol as hunt_protocol

import protocols.tool_routing as tool_routing

  
  
  

init(autoreset=True)

  

law_client = LogsQueryClient(credential=DefaultAzureCredential())

  

openai_client = OpenAI(api_key=API_KEY)

  
  

user_message = prompts.get_user_message()

  

print(f"{Fore.WHITE}\nDeciding log search parameters based on user request...\n")

  

args = tool_routing.get_log_query_from_agent(openai_client, user_message)

  

# Unpack the structured arguments from the tool call

caller = ""

device = ""

table = args['table_name']

if "device" in args:

    device = args['device_name']

if "caller" in args:

    caller = args['caller']

time_range = args['time_range_hours']

fields = ', '.join(map(str, args["fields"]))

  
  

print(f"{Fore.LIGHTGREEN_EX}Log search parameters finalized:")

print(f"{Fore.WHITE}Table Name:  {table}")

print(f"{Fore.WHITE}Caller:      {caller}")

print(f"{Fore.WHITE}Device Name: {device}")

print(f"{Fore.WHITE}Time Range:  {time_range} hour(s)")

print(f"{Fore.WHITE}Fields:      {fields}\n")

  
  

law_query_results = queries.query_devicelogonevents(

    log_analytics_client=law_client,

    workspace_id=LOG_ANALYTICS_WORKSPACE_ID,

    timerange_hours=time_range,

    table_name=table,

    device_name=device,

    caller=caller,

    fields=fields)

  

# Truncate results for LLM context limit

lines = law_query_results.split('\n')

if len(lines) > 100:

    print(f"{Fore.YELLOW}Truncating log results from {len(lines)} to 100 rows for analysis.")

    law_query_results = '\n'.join(lines[:101])

  

print(f"{Fore.LIGHTGREEN_EX}Building threat hunt prompt/instructions...\n")

  

threat_hunt_user_message = build_threat_hunt_prompt(

    user_prompt=user_message["content"],

    table_name=table,

    log_data=law_query_results

)

  

print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...")

  

start_time = time.time()

  

hunt_results = hunt_protocol.hunt(

    openai_client=openai_client,

    threat_hunt_system_message=SYSTEM_PROMPT_THREAT_HUNT,

    threat_hunt_user_message=threat_hunt_user_message,

    openai_model=models.GPT_5

)

  

elapsed = time.time() - start_time

  

print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results)} {Fore.WHITE}potential threats!")

print(f"Press [Enter] or [Return] to see results.")

input()

  

utilities.display_threats(threat_list=hunt_results)

  

print("fin.")
