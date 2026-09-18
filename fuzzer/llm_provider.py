"""
llm_provider.py

Lightweight HTTP client for connecting to real LLM providers
(OpenAI-compatible, Ollama, Google Gemini) without requiring heavy external SDKs.
Supports chat completions with tool/function calling definitions.
"""

import json
import os
from typing import List, Dict, Any, Optional
import requests


class LLMProviderError(Exception):
    pass


class LLMClient:
    """
    Standard interface for calling LLMs.
    Supported providers:
      - 'mock': offline rule-based stand-in
      - 'openai-compatible': any /v1/chat/completions endpoint (OpenAI, Groq, vLLM, etc.)
      - 'ollama': local Ollama instance (defaults to http://localhost:11434/v1)
      - 'gemini': Google Gemini generateContent API
    """

    def __init__(
        self,
        provider: str = "mock",
        model: Optional[str] = None,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.provider = (provider or "mock").lower()
        self.timeout = timeout

        if self.provider == "ollama":
            self.endpoint = endpoint or "http://localhost:11434/v1/chat/completions"
            self.model = model or "llama3.2"
            self.api_key = api_key or os.environ.get("OLLAMA_API_KEY", "ollama")
        elif self.provider in ("openai", "openai-compatible"):
            self.endpoint = endpoint or "https://api.openai.com/v1/chat/completions"
            self.model = model or "gpt-4o-mini"
            self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        elif self.provider == "gemini":
            self.model = model or "gemini-1.5-flash"
            self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
            self.endpoint = (
                endpoint
                or f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            )
        else:
            self.provider = "mock"
            self.model = "mock-agent"
            self.endpoint = None
            self.api_key = None

    def chat_with_tools(
        self,
        system_prompt: str,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Sends a conversation to the LLM and returns a standard dictionary:
        {
            "content": str,
            "tool_calls": [
                {"name": "...", "arguments": {...}}
            ]
        }
        """
        if self.provider == "mock":
            return {"content": "", "tool_calls": []}

        if self.provider in ("openai", "openai-compatible", "ollama"):
            return self._call_openai_compatible(system_prompt, messages, tools)
        elif self.provider == "gemini":
            return self._call_gemini(system_prompt, messages, tools)

        raise LLMProviderError(f"Unsupported provider: {self.provider}")

    def _call_openai_compatible(
        self,
        system_prompt: str,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        full_messages = [{"role": "system", "content": system_prompt}] + messages
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "temperature": 0.0,
        }

        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
                for t in tools
            ]

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                raise LLMProviderError(
                    f"Provider returned status {resp.status_code}: {resp.text}"
                )
            data = resp.json()
            choice = data.get("choices", [{}])[0].get("message", {})
            content = choice.get("content") or ""
            raw_tool_calls = choice.get("tool_calls", [])

            parsed_tool_calls = []
            for tc in raw_tool_calls:
                fn = tc.get("function", {})
                fn_name = fn.get("name")
                fn_args_raw = fn.get("arguments", "{}")
                if isinstance(fn_args_raw, str):
                    try:
                        fn_args = json.loads(fn_args_raw)
                    except Exception:
                        fn_args = {"raw": fn_args_raw}
                else:
                    fn_args = fn_args_raw or {}
                parsed_tool_calls.append({"name": fn_name, "arguments": fn_args})

            return {"content": content, "tool_calls": parsed_tool_calls}
        except requests.RequestException as exc:
            raise LLMProviderError(f"Network error calling {self.endpoint}: {exc}")

    def _call_gemini(
        self,
        system_prompt: str,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        url = self.endpoint
        if self.api_key:
            url = f"{url}?key={self.api_key}"

        contents = []
        for m in messages:
            role = "user" if m.get("role") == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m.get("content", "")}]})

        payload: Dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.0},
        }

        if tools:
            declarations = [
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                }
                for t in tools
            ]
            payload["tools"] = [{"functionDeclarations": declarations}]

        headers = {"Content-Type": "application/json"}
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                raise LLMProviderError(
                    f"Gemini API returned status {resp.status_code}: {resp.text}"
                )
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return {"content": "", "tool_calls": []}

            parts = candidates[0].get("content", {}).get("parts", [])
            content_pieces = []
            parsed_tool_calls = []
            for part in parts:
                if "text" in part:
                    content_pieces.append(part["text"])
                if "functionCall" in part:
                    fc = part["functionCall"]
                    parsed_tool_calls.append({
                        "name": fc.get("name"),
                        "arguments": fc.get("args", {}),
                    })

            return {
                "content": "".join(content_pieces),
                "tool_calls": parsed_tool_calls,
            }
        except requests.RequestException as exc:
            raise LLMProviderError(f"Network error calling Gemini: {exc}")
