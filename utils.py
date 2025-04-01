#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  : xrayl
# @Link    : 1worl0x00@gmail.com
# @Date    : 23/03/2025
# @Description: 

from typing import Dict, Optional, Any
import re
import json
import logging

logger = logging.getLogger(__name__)

def extract_json_from_markdown(text: str) -> Optional[Dict[str, Any]]:
    """
    从Markdown文本中提取JSON数据，并移除JSON中的注释
    """
    try:
        # 使用正则匹配JSON数据
        json_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
            
            # 移除JSON中的注释 (如 // 注释内容)
            json_str = re.sub(r'\s*//.*?$', '', json_str, flags=re.MULTILINE)
            
            # 确保JSON格式正确
            return json.loads(json_str)
        return None
    except Exception as e:
        logger.error(f"从Markdown提取JSON失败: {str(e)}")
        
        # 如果解析失败，尝试更强力的方法
        try:
            # 尝试直接提取JSON对象，不依赖于```json标记
            json_pattern = r'\{\s*"\w+"\s*:\s*.*?\s*\}'
            json_match = re.search(json_pattern, text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                return json.loads(json_str)
            
            # 如果上述方法失败，尝试手动构建JSON
            cve_match = re.search(r'"cve"\s*:\s*"([^"]+)"', text)
            vendor_match = re.search(r'"vendor"\s*:\s*"([^"]+)"', text)
            language_match = re.search(r'"language"\s*:\s*"([^"]+)"', text)
            trace_language_match = re.search(r'"trace_language"\s*:\s*"([^"]+)"', text)
            is_cause_match = re.search(r'"is_cause"\s*:\s*"([^"]+)"', text)
            function_match = re.search(r'"function"\s*:\s*"([^"]+)"', text)
            
            result = {}
            if cve_match: result['cve'] = cve_match.group(1)
            if vendor_match: result['vendor'] = vendor_match.group(1)
            if language_match: result['language'] = language_match.group(1)
            if trace_language_match: result['trace_language'] = trace_language_match.group(1)
            if is_cause_match: result['is_cause'] = is_cause_match.group(1)
            if function_match: result['function'] = function_match.group(1)
            
            if result:  # 如果至少找到了一个字段
                return result
        except Exception as e2:
            logger.error(f"备用JSON提取方法也失败: {str(e2)}")
        
        return None