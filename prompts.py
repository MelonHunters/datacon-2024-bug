#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : xrayl
# @Link    : 1worl0x00@gmail.com
# @Date    : 23/03/2025
# @Description: 

from langchain.prompts import PromptTemplate

EXTRACT_PROMPT = """
    User question: if given some text and script from a html website, please summarize the following information:
    Vulnerability ID: The CVE ID corresponding to the vulnerability described in the article, in the format CVE-XXXX-XXXX. If there is no specific ID, it is NULL.
    Vendor or Product Name: The vendor or product name corresponding to the vulnerability described in the article. If both exist, take the vendor name.
    Programming Language: The programming language used by the object with the vulnerability. If multiple languages are involved, take the language where the vulnerability point is located.
    Backtrace Lanuage: The programming language suggested by back trace chain or stack trace chain, default is NULL if there is no back trace chain.
    Is Cause Analysis: Whether the article contains an explanation of the cause of the vulnerability. TRUE if yes, FALSE if no.
    Dangerous Function: Directly-mentioned dangerous function that triggers the vulnerability described in the article, such as memmove, do_system. If there is no such function, it is NULL.
    
    <context>
    {ocr_result}
    </context>
    answer user's question with the information in <context>
    output format: {format_instructions}

    let us analyse it step by step, give us your analyse procedure, and be careful about the following things:
    1.if there are many CVE IDs in an article, only output one CVE ID that is most relevant to the text;
    2.all vendor that you need to check is listed in {vendor_list}, different items are separated with ';', NULL means no vendor or product name are found;
    3.your vendor output must be exactly the same as a certain item of the list, DO NOT add other words such as changing "Adobe" into "Adobe Reader";
    4.if many vendors are located, only output one vendor that is closed to the CVE ID information and is directly mentioned(eg: output Android instead of Google if find "Android" in text but no "google" in text);
    5.all programming languages that you need to check is listed in {language_list}, different items are separated with ';', NULL means no other languages are found, your Programming Language output must be in the list;
    6.the programming language of all iot device products are all "C", it can be judged by brand and product. For example, if you find a vulnerability in TP-Link, all TP-Link products are iot devices, therefore the language is "C";
    7.If there are many programming languages found, output the language that is most relevant to the vulnerability trigger point(near the Dangerous Function output); 
    8.Dangerous function must be directly mentioned in the text, you can use some content relevant to the dangerous function if it is not directly found(eg: output telnet if there is no system);
    9.Regard "Is Cause Analysis" to be true when the article describes the code near a dangerous function(Attacking codes such as PoC is not this type of code), return FALSE if there are no content about code nearing dangerous function;
    10.When judging backtrace language, carefully find potential c++ functions in the trace, output C++ if it is a mix of C and C++.(some c++ functions containing "::" such as "ios::sync_with_stdio", and ".cpp" in comment also shows that it is C++);
    11.please ensure that the output json is a legal json file, and output your analyse procedure.
"""
extract_prompt_template = PromptTemplate(
    input_variables=[
        "ocr_result",
        "format_instructions",
        "vendor_list",
        "language_list"
    ],
    template=EXTRACT_PROMPT
)


SOURCE_PROMPT = """
        User question: if given some text and script from a html website, please summarize the following information:
        POC/EXP Presence: Determine if the article contains a Proof of Concept (POC) or exploit code (EXP). If present, output TRUE; otherwise, output FALSE.
        POC/EXP Explanation: Identify whether the article provides an explanation or commentary about the POC/EXP code. If explanations exist, output TRUE; otherwise, output FALSE.
        Is Related: Whether the article is related to vulnerability mining. If it is not related to vulnerability mining or does not involve specific vulnerabilities, return FALSE, otherwise, return TRUE.

        <context>
        {ocr_result}
        </context>
        answer user's question with the information in <context>
        output format: {format_instructions}


        let us analyse it step by step, give us your analyse procedure, and be careful about the following things:
        1. Is related should be TRUE if the article is about a certain vulnerability(eg:has a CVE id);
        2. Is related should be FALSE if the article describes cyber security, but do not describe vulnerability mining(eg: it describes virus);
        3. If the article contains a functional code snippet, a series of steps or instructions, or commands that demonstrate how to exploit a vulnerability, carry out an attack, or crash the vulnerable system, mark POC/EXP Presence as TRUE; otherwise, mark it as FALSE.

        4. Step 4.1-4.4 are used for POC/EXP Explanations:
        4.1 POC/EXP Explanation requires a field-by-field explanation of each parameter or field involved in the POC/EXP, and this explanation must be separate from the POC code block;
        4.2 The explanation must detail all fields or parameters (e.g., HTTP headers, input parameters, function arguments) and cannot rely on common commands (e.g., telnet, curl) or explain only one field;
        4.3 If the explanation does not meet these criteria or is not separate from the POC code block, mark POC/EXP Explanation as FALSE;
        4.4 POC/EXP Explanations are text close to POC/EXP(code itself is not explaination), comment of code is also regarded as explainations.

        5. Focused Analysis:
        5.1. Pay attention to both the presence of POC/EXP and the presence of explanation.
        5.2. When POC/EXP Presence is TRUE, verify if there is enough explanation to mark POC/EXP Explanation as TRUE.
        5.3. If the code is present but lacks detailed explanation or commentary about the specific fields in the POC/EXP, mark POC/EXP Explanation as FALSE.

        6.please ensure that the output json is a legal json file, and output your analyse procedure.
"""
source_prompt_template = PromptTemplate(
    input_variables=["ocr_result","format_instructions"],
    template=SOURCE_PROMPT
)

system_prompt = """
You are a cyber security engineer whose job is to look at vulnerability disclosure websites and summarize vulnerability information, you have the knowledge about CVE, poc(proof of concept) and exp(exploit), know all kinds of common-used programming language, and can read both English and Chinese.
"""
    
# system_prompt = PromptTemplate(
#     template="You are a cyber security engineer whose job is to look at vulnerability disclosure websites and summarize vulnerability information, you have the knowledge about CVE, poc(proof of concept) and exp(exploit), know all kinds of common-used programming language, and can read both English and Chinese.",
# )