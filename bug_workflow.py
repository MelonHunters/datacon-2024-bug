#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : xrayl
# @Link    : 1worl0x00@gmail.com
# @Date    : 23/03/2025
# @Description: 

import logging
from typing import List, TypedDict
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from model import response_schemas_former, response_schemas_latter
from langchain_openai import ChatOpenAI
from prompts import *
import os
import dotenv
from langchain_core.messages import SystemMessage
from utils import extract_json_from_markdown
import json

dotenv.load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnInfo(TypedDict):
    cve: str
    vendor: str
    programming_language: str
    dangerous_function: str
    is_cause_analysis: bool
    trace_language: str
    is_cause: bool
    function: str

class SourceInfo(TypedDict):
    is_poc: bool
    is_related: bool
    is_explain: bool

class InfoState(TypedDict):
    ocr_result: str
    vuln_info_list: List[VulnInfo]
    vendor_list_str: str
    source_info_list: List[SourceInfo]
    language_list_str: str
    final_result: VulnInfo
    execution_count: int


class BugWorkflow():
    def __init__(self):
        self.llm = self._create_llm()
    
    def _create_outparser(self, response_schemas: List[ResponseSchema]):
        return StructuredOutputParser.from_response_schemas(response_schemas)
    
    def _create_llm(self):
        llm = ChatOpenAI(model_name=os.getenv("model_name"), api_key=os.getenv("apikey"), base_url=os.getenv("endpoint"), temperature=0)
        return llm
    
    def _create_prompt(self, prompt_type: str = 'vuln'):
        if prompt_type == 'vuln':
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=system_prompt),
                HumanMessagePromptTemplate(prompt=extract_prompt_template)
            ])
        else:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=system_prompt),
                HumanMessagePromptTemplate(prompt=source_prompt_template)
            ])
        return prompt

    def get_vuln_info(self, state: InfoState) -> InfoState:
        vuln_prompt_template = self._create_prompt(prompt_type='vuln')
        vuln_outparser = self._create_outparser(response_schemas_former)
        vuln_prompt = vuln_prompt_template.invoke(
            {
                'ocr_result': state.get('ocr_result'),
                'format_instructions': vuln_outparser.get_format_instructions(),
                'vendor_list': state.get('vendor_list_str'),
                'language_list': state.get('language_list_str')
            }
        )
        # 处理基本字段
        response = self.llm.invoke(vuln_prompt)
        j_response = vuln_outparser.parse(json.dumps(extract_json_from_markdown(response.content)))
        vuln_info = VulnInfo(
            cve=j_response['cve'],
            vendor=j_response['vendor'],
            programming_language=j_response['language'],
            dangerous_function=j_response['function'],
            is_cause_analysis=j_response['is_cause'],
        )

        # 处理文章字段
        source_prompt_template = self._create_prompt(prompt_type='source')
        source_outparser = self._create_outparser(response_schemas_latter)
        source_prompt = source_prompt_template.invoke(
            {
                'ocr_result': state.get('ocr_result'),
                'format_instructions': source_outparser.get_format_instructions(),
            }
        )
        source_response = self.llm.invoke(source_prompt)
        j_source_response = source_outparser.parse(json.dumps(extract_json_from_markdown(source_response.content)))
        print(j_source_response)
        source_info = SourceInfo(
            is_poc=j_source_response['poc'],
            is_related=j_source_response['is_related'],
            is_explain=j_source_response['is_explain']
        )
        return {
            'vuln_info_list': state['vuln_info_list'] + [vuln_info],
            'source_info_list': state['source_info_list'] + [source_info],
            'execution_count': state['execution_count'] + 1
        }
    
    def should_continue(self, state: InfoState) -> str:
        if state['execution_count'] <= 3:
            return "task_executor"
        else:
            return "finalize"
        
    # def vote(self, state: InfoState, vuln_info_list: List[VulnInfo]):
    #     print("vote")


    def vote(self, state: InfoState, vuln_info_list: List[VulnInfo], source_info_list: List[SourceInfo]):
        vendor_list = state.get('vendor_list_str').split(';')
        language_list = state.get('language_list_str').split(';')

        if len(vuln_info_list) == 3:
            vuln_info_0 = vuln_info_list[0]
            vuln_info_1 = vuln_info_list[1]
            vuln_info_2 = vuln_info_list[2]
        
        vuln_info = {}

        # 应该先优先处理source_info
        source_info_0 = source_info_list[0]
        source_info_1 = source_info_list[1]
        source_info_2 = source_info_list[2]
        source_info_3 = source_info_list[3]

        # >2策略，用于判断是否包含漏洞分析
        related_vote = 0
        if source_info_0['is_related'] == 'FALSE':
            related_vote += 1
        if source_info_1['is_related'] == 'FALSE':
            related_vote += 1
        if source_info_2['is_related'] == 'FALSE':
            related_vote += 1
        if source_info_3['is_related'] == 'FALSE':
            related_vote += 1
        if related_vote >= 2:
            return {
                'final_result': {}
            }

        # TODO: 2+1投票策略存在问题，原始实现似乎有点问题
        if vuln_info_0['vendor'] not in vendor_list and vuln_info_1['vendor'] in vendor_list:
            vuln_info['vendor'] = vuln_info_1['vendor']
        elif vuln_info_0['vendor'] not in vendor_list and vuln_info_1['vendor'] not in vendor_list:
            if vuln_info_2['vendor'] in vendor_list:
                vuln_info['vendor'] = vuln_info_2['vendor']
            else:
                vuln_info['vendor'] = 'NULL'
        
        if vuln_info_0['vendor'] != vuln_info_1['vendor']:
            if vuln_info['vendor'] == 'NULL':
                pass
                
        # TODO：1否3策略，用于判断是否包含PoC和PoC的分析

        if vuln_info['is_POC']=="FALSE" and vuln_info["is_explain"]=="TRUE":
            vuln_info["is_explain"] = "FALSE"
        
        return {
            'final_result': vuln_info
        }
            

    def finish(self, state: InfoState):
        vuln_info_list = state['vuln_info_list']
        source_info_list = state['source_info_list']
        self.vote(state=state, vuln_info_list=vuln_info_list, source_info_list=source_info_list)
