#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : xrayl
# @Link    : 1world0x00@gmail.com
# @Date    : 23/03/2025
# @Description: 

from langchain.output_parsers import StructuredOutputParser, ResponseSchema


response_schemas_former = [
    ResponseSchema(name="cve", description="Vulnerability ID"),
    ResponseSchema(name="vendor", description="Vendor or Product Name"),
    ResponseSchema(name="language", description="Programming Language"),
    ResponseSchema(name="trace_language", description="Backtrace Lanuage"),
    ResponseSchema(name="is_cause", description="Is Cause Analysis"),
    ResponseSchema(name="function", description="Dangerous Function Name"),
]

response_schemas_latter = [
    ResponseSchema(name="poc", description="POC/EXP Presence"),
    ResponseSchema(name="is_related", description="Is Related"),
    ResponseSchema(name="is_explain", description="Is Explain"),
]
    