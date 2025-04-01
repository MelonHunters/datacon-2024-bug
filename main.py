#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : xrayl
# @Link    : 1worl0x00@gmail.com
# @Date    : 23/03/2025
# @Description: 

from typing import TypedDict, List
from langgraph.graph import StateGraph, START, END
from bug_workflow import BugWorkflow, InfoState

if __name__ == '__main__':
    # 构建图
    builder = StateGraph(InfoState)
    bug_workflow = BugWorkflow()
    builder.add_node("task_executor", bug_workflow.get_vuln_info)
    builder.add_node("finalize", bug_workflow.finish)

    # 设置边和条件
    builder.add_edge(START, "task_executor")
    builder.add_conditional_edges("task_executor", bug_workflow.should_continue)
    builder.add_edge("finalize", END)

    graph = builder.compile()

    vendor_str="PHP;Linksys;Google;Asus;华夏;Mongoose;OFFICE;Mail GPU;SnakeYAML;WebKit;Microsoft;OpenCart;Cajviewer;ZZCMS;Linux;Askey;Oracle;Github;Calibre;Typora;Bitrix24;bluetooth_stack;Foxit;Netgear;SolarWinds;TP-Link;Samsung;Adobe;Singtel;Acrobat;CS-Cart;Tesla;Apple;SEACMS;Shopware;Gitlab;Chamilo;Windows;LMS;Juniper;Qemu;OwnCloud;NULL;Confluence;Apache;D-Link;F5;Prolink;Trend;Icecast;Hancom;Schneider;Mikrotik;Netatalk;NodeBB;Ivanti;Openwrt;Huawei;Dolibarr;KMPlayer;Android;EXIM;MarkText;Cisco;Razer;Obsidian;然之;Fortinet;Sudo"
    program_str="JAVA;PHP;JAVASCRIPT;NULL;PYTHON;C;HTML;SHELL;C#;TYPESCRIPT;ASP;RUBY;C++"

    security_advisory = """
    Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code 
        Execution and/or Information disclosure and/or malicious content added 
        to uploaded files via write enabled Default Servlet in Apache Tomcat.

        This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 
        10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98.

        If all of the following were true, a malicious user was able to view 
        security sensitive files and/or inject content into those files:
        - writes enabled for the default servlet (disabled by default)
        - support for partial PUT (enabled by default)
        - a target URL for security sensitive uploads that was a sub-directory 
        of a target URL for public uploads
        - attacker knowledge of the names of security sensitive files being uploaded
        - the security sensitive files also being uploaded via partial PUT

        If all of the following were true, a malicious user was able to 
        perform remote code execution:
        - writes enabled for the default servlet (disabled by default)
        - support for partial PUT (enabled by default)
        - application was using Tomcat's file based session persistence with the 
        default storage location
        - application included a library that may be leveraged in a 
        deserialization attack

        Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.98, 
        which fixes the issue.
    """
    initial_state = {
        'ocr_result': security_advisory,
        'vendor_list_str': vendor_str,
        'language_list_str': program_str,
        'vuln_info_list': [],
        'source_info_list': [],
        'execution_count': 0
    }
    # TODO: 遍历情报文件夹，批量处理情报
    # 使用图
    result = graph.invoke(initial_state)
