# -*- coding: utf-8 -*-
"""
AI client for Genesect - handles communication with AI providers.
"""

import threading
import functools
import time
import contextlib
import importlib
import io
import json
import os
import shutil
import subprocess
import warnings
import itertools

import ida_kernwin

from genesect.qt_compat import openai, httpx, anthropic, genai, gemini_backend
from genesect.config import CONFIG, LOGGER
from genesect.cli_runner import CLICancelled, run_cli_command
from genesect.provider_config import (
    SIGNED_IN_CLI_PROVIDERS,
    profile_from_config,
    request_options_from_config,
)
from genesect import chatgpt_oauth


# Global state for UI to check
_ai_busy_count = 0
AI_CANCEL_REQUESTED = False
_REQUEST_IDS = itertools.count(1)
_BUSY_LOCK = threading.Lock()

_CONTEXT_LIMIT_ERROR_MARKERS = (
    "context length",
    "context window",
    "maximum context",
    "trying to keep the first",
    "prompt is too long",
    "context_length_exceeded",
    "too many tokens",
)


def _format_provider_error(provider, model, request_id, error):
    """Build a clear IDA Output diagnostic for a failed provider request."""
    detail = str(error).strip() or type(error).__name__
    normalized = detail.lower()
    context_limit = any(marker in normalized for marker in _CONTEXT_LIMIT_ERROR_MARKERS)
    category = "MODEL CONTEXT ERROR" if context_limit else "AI PROVIDER ERROR"
    explanation = (
        "The model server rejected the prompt because it exceeds the model's loaded "
        "context window. This is not a Genesect plugin failure."
        if context_limit else
        "The request failed while communicating with the configured AI provider."
    )
    return (
        f"\n[Genesect] [{category}] Request {request_id}\n"
        f"  Provider: {provider}\n"
        f"  Model: {model or '<not configured>'}\n"
        f"  Explanation: {explanation}\n"
        f"  Provider details: {detail}\n"
    )


def _quiet_optional_import(module_name):
    """Import an optional provider without leaking its dependency diagnostics."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r'Field "model_(?:id|name)" has conflict with protected namespace.*',
            category=UserWarning,
        )
        # Some provider discovery code prints missing optional integrations
        # directly instead of reporting them through Python's warning system.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return importlib.import_module(module_name)


def _load_anthropic():
    global anthropic
    if anthropic is None:
        try:
            anthropic = _quiet_optional_import("anthropic")
        except ImportError:
            return None
    return anthropic


def _load_gemini():
    global genai, gemini_backend
    if genai is not None:
        return genai
    try:
        genai = _quiet_optional_import("google.genai")
        gemini_backend = "google-genai"
    except ImportError:
        try:
            genai = _quiet_optional_import("google.generativeai")
            gemini_backend = "google-generativeai"
        except ImportError:
            genai = None
            gemini_backend = None
    return genai

class AIBusyStatus:
    def __bool__(self):
        return _ai_busy_count > 0
    def __int__(self):
        return _ai_busy_count
    def __repr__(self):
        return str(_ai_busy_count > 0)
    def __eq__(self, other):
        if isinstance(other, bool):
            return (_ai_busy_count > 0) == other
        return super().__eq__(other)

AI_BUSY = AIBusyStatus()

class SimpleAI:
    def __init__(self, config):
        self.config = config
        self.provider = "openai"
        self.client = None
        self.async_func = None
        self.profile = profile_from_config(config)
        self.request_options = request_options_from_config(config)
        self._request_lock = threading.Lock()
        self._cancelled_requests = set()

        self.determine_provider()
        self.init_client()

    def cancel_request(self, request_id):
        with self._request_lock:
            self._cancelled_requests.add(int(request_id))

    def _request_cancelled(self, request_id):
        with self._request_lock:
            return int(request_id) in self._cancelled_requests

    def determine_provider(self):
        self.profile = profile_from_config(self.config)
        self.provider = self.profile.client_name
        LOGGER.log(f"AI provider selected: {self.profile.name}")

    def log_provider_info(self):
        info = f"Active AI Provider: {self.profile.name} (model: {self.profile.model}"
        if self.profile.url:
            info += f", URL: {self.profile.url}"
        info += ")"
        LOGGER.log(info)

    def init_client(self):
        if self.profile.name in SIGNED_IN_CLI_PROVIDERS:
            executable = (self.profile.key or "").strip()
            if not executable:
                executable = {
                    "CodexCLI": "codex",
                    "ClaudeCode": "claude",
                    "AntigravityCLI": "agy",
                    "GeminiCLI": "gemini",
                    "QwenCode": "qwen",
                    "OpenCode": "opencode",
                    "HermesCLI": "hermes-agent",
                }.get(self.profile.name, "")
            self.client = executable
            return

        if httpx is None:
            LOGGER.log("httpx is unavailable; AI client initialization skipped.")
            return
        read_timeout = float(self.request_options.timeout_seconds)
        timeout = httpx.Timeout(connect=min(15.0, read_timeout), read=read_timeout, write=30.0, pool=10.0)
        http_client = httpx.Client(proxy=self.config.proxy, timeout=timeout) if self.config.proxy else httpx.Client(timeout=timeout)

        # Helper to clean URLs
        def clean_url(u):
            if not u: return u
            u = u.strip()
            if u.endswith('/'): u = u[:-1]
            return u

        if self.provider == "openai":
            if not openai or not self.profile.key: return
            self.client = openai.OpenAI(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "chatgptaccount":
            if not openai:
                LOGGER.log("OpenAI SDK missing; ChatGPT account provider unavailable.")
                return
            try:
                token = chatgpt_oauth.get_access_token()
            except Exception as exc:
                LOGGER.log("ChatGPT account not ready: %s" % exc)
                return
            self.client = openai.OpenAI(api_key=token, base_url="https://api.openai.com/v1", http_client=http_client)

        elif self.provider == "deepseek":
            if not openai or not self.profile.key: return
            self.client = openai.OpenAI(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "ollama":
            if not openai: return
            self.client = openai.OpenAI(api_key="ollama", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "lmstudio":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.profile.key or "lm-studio", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "custom":
            if not openai: return
            self.client = openai.OpenAI(api_key=self.profile.key or "not-required", base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "anthropic":
            anthropic_sdk = _load_anthropic()
            if not anthropic_sdk or not self.profile.key:
                LOGGER.log("Anthropic library or Key missing.")
                return
            self.client = anthropic_sdk.Anthropic(api_key=self.profile.key, base_url=clean_url(self.profile.url), http_client=http_client)

        elif self.provider == "gemini":
            gemini_sdk = _load_gemini()
            if not gemini_sdk or not self.profile.key:
                LOGGER.log("Google GenAI library or Key missing.")
                return
            if gemini_backend == "google-genai":
                self.client = gemini_sdk.Client(api_key=self.profile.key)
            else:
                gemini_sdk.configure(api_key=self.profile.key)
                self.client = "gemini_configured"

    def query_model_async(self, prompt, callback, additional_options=None, on_chunk=None, on_status=None):
        """
        Query AI model asynchronously. 
        on_chunk(text) is called for each streamed part if streaming is supported.
        on_status(count, text) is called for status updates.
        callback(response, finish_reason) is called when finished.
        """
        global AI_BUSY, AI_CANCEL_REQUESTED, _ai_busy_count
        request_id = next(_REQUEST_IDS)
        with _BUSY_LOCK:
            if _ai_busy_count == 0:
                AI_CANCEL_REQUESTED = False
        if additional_options is None:
            additional_options = {}
        else:
            additional_options = dict(additional_options)
        additional_options.setdefault("max_completion_tokens", self.request_options.max_completion_tokens)
        additional_options.setdefault("temperature", self.request_options.temperature)

        def request_cancelled():
            return AI_CANCEL_REQUESTED or self._request_cancelled(request_id)

        def invoke_callback(**payload):
            """Pass lifecycle metadata only when the callback accepts it."""
            import inspect
            try:
                base_func = callback.func if isinstance(callback, functools.partial) else callback
                signature = inspect.signature(base_func)
                has_kwargs = any(
                    parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in signature.parameters.values()
                )
                if has_kwargs:
                    callback(**payload)
                else:
                    filtered = {key: value for key, value in payload.items() if key in signature.parameters}
                    callback(**filtered)
            except (TypeError, ValueError):
                callback(response=payload.get("response"))

        def call_with_retry(operation):
            attempts = self.request_options.retry_attempts + 1
            for attempt in range(attempts):
                try:
                    return operation()
                except Exception as exc:
                    message = str(exc).lower()
                    permanent = any(token in message for token in (
                        "401", "403", "unauthorized", "forbidden", "invalid api key",
                        "model not found", "404", "context length", "context window",
                        "maximum context", "trying to keep the first", "prompt is too long",
                        "context_length_exceeded", "too many tokens",
                    ))
                    if permanent or attempt >= attempts - 1 or request_cancelled():
                        raise
                    delay = self.request_options.retry_backoff_seconds * (2 ** attempt)
                    LOGGER.log(
                        f"AI request {request_id} retry {attempt + 1}/"
                        f"{self.request_options.retry_attempts} in {delay:.1f}s: {type(exc).__name__}"
                    )
                    if on_status:
                        safe_execute(lambda a=attempt + 1, d=delay: on_status(0, f"Retry {a} in {d:.1f}s..."))
                    if delay:
                        time.sleep(delay)

        def safe_execute(func):
            def wrapper():
                try:
                    func()
                except:
                    pass
                return False
            try:
                ida_kernwin.execute_ui_requests((wrapper,))
            except:
                pass

        def thread_target():
            global _ai_busy_count, AI_CANCEL_REQUESTED
            with _BUSY_LOCK:
                _ai_busy_count += 1
            full_content = ""
            finish_reason = "stop"
            
            try:
                LOGGER.log(f"Sending request to {self.provider} (Streaming: {on_chunk is not None})...")
                
                # Update UI that we are sending the request
                if on_status:
                    safe_execute(lambda: on_status(0, "Sending request..."))

                if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                    if not self.client: raise ValueError(f"Client for {self.provider} not initialized.")

                    if isinstance(prompt, list):
                        messages = prompt
                    else:
                        messages = [{"role": "user", "content": prompt}]
                    model = self.profile.model

                    valid_args = {"model": model, "messages": messages}
                    is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                    
                    if "max_completion_tokens" in additional_options:
                         if is_reasoning:
                             valid_args["max_completion_tokens"] = additional_options["max_completion_tokens"]
                         else:
                             valid_args["max_tokens"] = additional_options["max_completion_tokens"]
                    
                    for k, v in additional_options.items():
                        if k == "max_completion_tokens": continue
                        if is_reasoning and k in ["temperature", "top_p", "response_format"]:
                            continue
                        valid_args[k] = v

                    if on_chunk:
                        valid_args["stream"] = True
                        stream = call_with_retry(lambda: self.client.chat.completions.create(**valid_args))
                        
                        buffer = ""
                        last_update = time.time()
                        
                        for chunk in stream:
                            if request_cancelled():
                                finish_reason = "cancelled"
                                break
                            
                            delta = chunk.choices[0].delta if chunk.choices else None
                            if not delta: continue
                            
                            content = getattr(delta, 'content', "") or ""
                            # Reasoning fallback for stream
                            reasoning = getattr(delta, 'reasoning_content', "") or getattr(delta, 'reasoning', "") or ""
                            if not content and reasoning: content = reasoning
                            
                            if content:
                                full_content += content
                                buffer += content
                                # Buffer updates to keep IDA thread responsive
                                if time.time() - last_update > 0.05 or len(buffer) > 100:
                                    def _do_update(txt=buffer): on_chunk(txt)
                                    safe_execute(_do_update)
                                    buffer = ""
                                    last_update = time.time()
                            
                            fin = getattr(chunk.choices[0], 'finish_reason', None)
                            if fin: finish_reason = fin
                        
                        # Flush remaining
                        if buffer:
                            def _flush_update(txt=buffer): on_chunk(txt)
                            safe_execute(_flush_update)
                    else:
                        response = call_with_retry(lambda: self.client.chat.completions.create(**valid_args))
                        msg = response.choices[0].message if response.choices else None
                        if msg:
                            full_content = getattr(msg, 'content', "") or ""
                            reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                            if not full_content.strip() and reasoning.strip(): full_content = reasoning
                            finish_reason = getattr(response.choices[0], 'finish_reason', 'stop')
                        else:
                            full_content = ""

                elif self.provider == "chatgptaccount":
                    if not self.client:
                        raise ValueError("ChatGPT account client not initialized. Sign in from Settings first.")
                    if not hasattr(self.client, "responses"):
                        raise ValueError("OpenAI SDK is too old for Responses API. Upgrade the openai package.")

                    token = chatgpt_oauth.get_access_token()

                    model = self.profile.model
                    if isinstance(prompt, list):
                        response_input = [
                            {
                                "role": item.get("role", "user"),
                                "content": item.get("content", ""),
                            }
                            for item in prompt
                            if item.get("role") != "system"
                        ]
                        system_text = "\n\n".join(
                            item.get("content", "")
                            for item in prompt
                            if item.get("role") == "system" and item.get("content")
                        )
                    else:
                        response_input = [{"role": "user", "content": prompt}]
                        system_text = ""

                    response_args = {
                        "model": model,
                        "input": response_input,
                        "store": False,
                        "stream": True,
                    }
                    if system_text:
                        response_args["instructions"] = system_text
                    if "max_completion_tokens" in additional_options:
                        response_args["max_output_tokens"] = additional_options["max_completion_tokens"]
                    # Rebuild after refresh so the bearer token is definitely current.
                    self.client = openai.OpenAI(api_key=token, base_url="https://api.openai.com/v1")
                    completed = False
                    buffer = ""
                    last_update = time.time()
                    stream_context = call_with_retry(lambda: self.client.responses.create(**response_args))
                    with stream_context as stream:
                        for event in stream:
                            if request_cancelled():
                                finish_reason = "cancelled"
                                break
                            event_type = getattr(event, "type", "")
                            if event_type == "response.output_text.delta":
                                text = getattr(event, "delta", "") or ""
                                if text:
                                    full_content += text
                                    buffer += text
                                    if on_chunk and (time.time() - last_update > 0.05 or len(buffer) > 100):
                                        def _do_update(txt=buffer): on_chunk(txt)
                                        safe_execute(_do_update)
                                        buffer = ""
                                        last_update = time.time()
                            elif event_type == "response.completed":
                                completed = True
                                finish_reason = "stop"
                            elif event_type == "response.incomplete":
                                finish_reason = "length"
                            elif event_type == "response.failed":
                                error = getattr(getattr(event, "response", None), "error", None)
                                code = getattr(error, "code", None) or "response_failed"
                                raise RuntimeError("ChatGPT account response failed: %s" % code)
                    if on_chunk and buffer:
                        def _flush_update(txt=buffer): on_chunk(txt)
                        safe_execute(_flush_update)
                    if not completed and finish_reason not in ("cancelled", "length"):
                        raise RuntimeError("ChatGPT account stream ended without response.completed.")

                elif self.provider == "anthropic":
                     if not self.client: raise ValueError("Anthropic client not initialized.")
                     
                     if isinstance(prompt, list):
                         messages = prompt
                     else:
                         messages = [{"role": "user", "content": prompt}]
                         
                     max_toks = additional_options.get("max_completion_tokens", 4096)
                     if on_chunk:
                         stream_context = call_with_retry(lambda: self.client.messages.stream(
                             model=self.profile.model,
                             max_tokens=max_toks,
                             messages=messages
                         ))
                         with stream_context as stream:
                             buffer = ""
                             last_update = time.time()
                             for text in stream.text_stream:
                                 if request_cancelled():
                                     finish_reason = "cancelled"
                                     break
                                 full_content += text
                                 buffer += text
                                 if time.time() - last_update > 0.05 or len(buffer) > 100:
                                     def _do_update(txt=buffer): on_chunk(txt)
                                     safe_execute(_do_update)
                                     buffer = ""
                                     last_update = time.time()
                             if buffer:
                                 def _flush_update(txt=buffer): on_chunk(txt)
                                 safe_execute(_flush_update)
                             
                             msg = stream.get_final_message()
                             finish_reason = getattr(msg, 'stop_reason', 'stop')
                             if finish_reason == 'max_tokens': finish_reason = 'length'
                     else:
                        message = call_with_retry(lambda: self.client.messages.create(
                            model=self.profile.model,
                            max_tokens=max_toks,
                            messages=messages
                        ))
                        full_content = message.content[0].text if hasattr(message.content[0], 'text') else str(message.content[0])
                        finish_reason = getattr(message, 'stop_reason', 'stop')
                        if finish_reason == 'max_tokens': finish_reason = 'length'

                elif self.provider == "gemini":
                     if not self.client: raise ValueError("Gemini not configured.")
                     
                     generation_config = {}
                     if "max_completion_tokens" in additional_options:
                         generation_config["max_output_tokens"] = additional_options["max_completion_tokens"]
                     if "temperature" in additional_options:
                         generation_config["temperature"] = additional_options["temperature"]
                     if "top_p" in additional_options:
                         generation_config["top_p"] = additional_options["top_p"]

                     if gemini_backend == "google-genai":
                         if isinstance(prompt, list):
                             history = []
                             for m in prompt:
                                 role = m.get("role", "user")
                                 if role == "assistant": role = "model"
                                 if role == "system": continue 
                                 history.append({"role": role, "parts": [{"text": m.get("content", "")}]})
                             
                             chat = self.client.chats.create(model=self.profile.model, history=history[:-1])
                             last_message = history[-1]["parts"][0]["text"]
                             
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: chat.send_message_stream(last_message, config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     txt = chunk.text or ""
                                     full_content += txt
                                     buffer += txt
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                     if chunk.candidates:
                                         fr = chunk.candidates[0].finish_reason
                                         if fr:
                                             if any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                                 finish_reason = "length"
                                             else:
                                                 finish_reason = "stop"
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                             else:
                                 response = call_with_retry(lambda: chat.send_message(last_message, config=generation_config))
                                 full_content = response.text or ""
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr and any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                         finish_reason = "length"
                                     else:
                                         finish_reason = "stop"
                                 except:
                                     finish_reason = "stop"
                         else:
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: self.client.models.generate_content_stream(
                                     model=self.profile.model,
                                     contents=prompt,
                                     config=generation_config
                                 ))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     txt = chunk.text or ""
                                     full_content += txt
                                     buffer += txt
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                     if chunk.candidates:
                                         fr = chunk.candidates[0].finish_reason
                                         if fr:
                                             if any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                                 finish_reason = "length"
                                             else:
                                                 finish_reason = "stop"
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                             else:
                                 response = call_with_retry(lambda: self.client.models.generate_content(
                                     model=self.profile.model,
                                     contents=prompt,
                                     config=generation_config
                                 ))
                                 full_content = response.text or ""
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr and any(x in str(fr).upper() for x in ["MAX_TOKENS", "LENGTH"]):
                                         finish_reason = "length"
                                     else:
                                         finish_reason = "stop"
                                 except:
                                     finish_reason = "stop"
                     else:
                         model = genai.GenerativeModel(self.profile.model)
                         if isinstance(prompt, list):
                             history = []
                             for m in prompt:
                                 role = m.get("role", "user")
                                 if role == "assistant": role = "model"
                                 if role == "system": continue 
                                 history.append({"role": role, "parts": [m.get("content", "")]})
                             
                             chat = model.start_chat(history=history[:-1])
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: chat.send_message(history[-1]["parts"][0], stream=True, generation_config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     full_content += chunk.text
                                     buffer += chunk.text
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                 
                                 try:
                                     fr = response_stream.last.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                             else:
                                 response = call_with_retry(lambda: chat.send_message(history[-1]["parts"][0], generation_config=generation_config))
                                 full_content = response.text
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                         else:
                             if on_chunk:
                                 response_stream = call_with_retry(lambda: model.generate_content(prompt, stream=True, generation_config=generation_config))
                                 buffer = ""
                                 last_update = time.time()
                                 for chunk in response_stream:
                                     if request_cancelled():
                                         finish_reason = "cancelled"
                                         break
                                     full_content += chunk.text
                                     buffer += chunk.text
                                     if time.time() - last_update > 0.05 or len(buffer) > 100:
                                         ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                         buffer = ""
                                         last_update = time.time()
                                 if buffer:
                                     ida_kernwin.execute_sync(functools.partial(on_chunk, buffer), ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_WRITE)
                                 
                                 try:
                                     fr = response_stream.last.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"
                             else:
                                 response = call_with_retry(lambda: model.generate_content(prompt, generation_config=generation_config))
                                 full_content = response.text
                                 try:
                                     fr = response.candidates[0].finish_reason
                                     if fr == 2: finish_reason = "length"
                                     else: finish_reason = "stop"
                                 except: finish_reason = "stop"

                elif self.profile.name in SIGNED_IN_CLI_PROVIDERS:
                    if not self.client:
                        raise ValueError("%s executable is not configured." % self.profile.name)
                    if on_status:
                        safe_execute(lambda: on_status(
                            0,
                            "Launching %s with its existing CLI sign-in..." % self.profile.name,
                        ))

                    def report_cli_wait(elapsed):
                        if not on_status:
                            return
                        hint = ""
                        if self.profile.name == "GeminiCLI" and elapsed >= 10:
                            hint = " If this is the first run, finish `gemini` sign-in in a terminal."
                        message = "Waiting for %s... %ds.%s" % (
                            self.profile.name, int(elapsed), hint,
                        )
                        safe_execute(lambda text=message: on_status(0, text))

                    try:
                        full_content = self._query_signed_in_cli(
                            prompt,
                            request_cancelled=request_cancelled,
                            status_callback=report_cli_wait,
                        )
                        finish_reason = "cancelled" if request_cancelled() else "stop"
                    except CLICancelled:
                        full_content = ""
                        finish_reason = "cancelled"

                LOGGER.log(f"Received response from {self.provider} ({len(full_content)} chars, reason: {finish_reason}).")

                # Wrap callback to ensure we pass response AND finish_reason
                def wrapped_callback(resp, reason):
                    invoke_callback(response=resp, finish_reason=reason, request_id=request_id)

                def _final_call():
                    wrapped_callback(resp=full_content, reason=finish_reason)
                safe_execute(_final_call)
            except Exception as e:
                LOGGER.log(f"AI Error ({self.provider}): {e}")
                error_msg = str(e)
                err_str = error_msg.lower()
                is_throttle = any(x in err_str for x in ["429", "too many requests", "quota", "rate limit"])
                output_message = _format_provider_error(
                    self.profile.name,
                    self.profile.model,
                    request_id,
                    e,
                )
                safe_execute(lambda text=output_message: print(text))
                
                def _do_err():
                    invoke_callback(
                        response=None,
                        error_msg=error_msg,
                        is_throttle=is_throttle,
                        request_id=request_id,
                    )
                        
                safe_execute(_do_err)
            finally:
                with self._request_lock:
                    self._cancelled_requests.discard(request_id)
                with _BUSY_LOCK:
                    _ai_busy_count = max(0, _ai_busy_count - 1)

        thread = threading.Thread(target=thread_target, name=f"GenesectAI-{request_id}", daemon=True)
        thread.start()
        return request_id

    def test_connection(self):
        prompt = "Reply with exactly: pong"
        try:
            if self.provider in ["openai", "deepseek", "ollama", "lmstudio", "custom"]:
                if not self.client: return False, "Client not initialized."
                
                model = self.profile.model

                is_reasoning = any(x in model.lower() for x in ["o1", "o3", "r1", "gpt-5", "reasoner", "reasoning", "thought"])
                valid_args = {"model": model, "messages": [{"role": "user", "content": prompt}]}
                
                if is_reasoning:
                    valid_args["max_completion_tokens"] = 128
                else:
                    valid_args["max_tokens"] = 30
                    valid_args["temperature"] = 0

                response = self.client.chat.completions.create(**valid_args)
                
                if not response.choices:
                    LOGGER.log(f"Test Connection: No choices. Full response: {response}")
                    return False, f"Connected but API returned no choices. (Model: {model})"

                msg = response.choices[0].message
                content = getattr(msg, 'content', "") or ""
                reasoning = getattr(msg, 'reasoning_content', "") or getattr(msg, 'reasoning', "") or ""
                refusal = getattr(msg, 'refusal', None)

                # Any valid response with choices = connection works.
                # Empty content can be a model quirk (e.g. some o1/o3 variants) — still counts as success.
                if refusal:
                    return False, f"Connected but model refused request: {refusal}"

                finish_reason = getattr(response.choices[0], 'finish_reason', None)
                if content.strip() or reasoning.strip():
                    return True, f"Connection successful! Model: {model}"

                # Got a valid response object but empty content — still a live connection
                LOGGER.log(f"Test Connection: Got valid response with empty content (finish_reason={finish_reason}). "
                           f"Full message: {msg}")
                return True, (f"Connection successful! (Model '{model}' replied with empty content — "
                              f"this is normal for some reasoning models. finish_reason={finish_reason})")

            elif self.provider == "chatgptaccount":
                if not self.client:
                    return False, "ChatGPT account client not initialized. Sign in from Settings first."
                if not hasattr(self.client, "responses"):
                    return False, "OpenAI SDK is too old for Responses API. Upgrade the openai package."
                token = chatgpt_oauth.get_access_token()
                self.client = openai.OpenAI(api_key=token, base_url="https://api.openai.com/v1")
                completed = False
                with self.client.responses.create(
                    model=self.profile.model,
                    input=[{"role": "user", "content": prompt}],
                    store=False,
                    stream=True,
                    max_output_tokens=128,
                ) as stream:
                    for event in stream:
                        event_type = getattr(event, "type", "")
                        if event_type == "response.output_text.delta":
                            pass
                        elif event_type == "response.failed":
                            error = getattr(getattr(event, "response", None), "error", None)
                            return False, "ChatGPT account response failed: %s" % (getattr(error, "code", None) or "unknown")
                        elif event_type == "response.completed":
                            completed = True
                if completed:
                    return True, "Connection successful! ChatGPT account model: %s" % self.profile.model
                return False, "ChatGPT account stream ended before completion."

            elif self.provider == "anthropic":
                if not self.client: return False, "Anthropic client not initialized."
                message = self.client.messages.create(
                    model=self.profile.model,
                    max_tokens=10,
                    messages=[{"role": "user", "content": prompt}]
                )
                return True, f"Connection successful!"

            elif self.provider == "gemini":
                if not self.client: return False, "Gemini not configured."
                model_name = self.profile.model
                if gemini_backend == "google-genai":
                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                    )
                else:
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content(prompt)
                return True, f"Connection successful!"

            elif self.profile.name in SIGNED_IN_CLI_PROVIDERS:
                if not self.client:
                    return False, "%s executable is not configured." % self.profile.name
                executable = self._resolve_cli_executable()
                if not executable:
                    return False, "%s executable not found. Configure the full path in Settings." % self.client
                output = self._query_signed_in_cli(
                    prompt,
                    timeout=min(self.request_options.timeout_seconds, 45),
                )
                if "pong" in output.lower():
                    return True, "Connection successful! %s answered using its signed-in session." % self.profile.name
                return True, "Signed-in CLI responded, but not with the expected test text."

            return False, f"Unknown provider: {self.provider}"
        except Exception as e:
            return False, f"Connection Failed: {str(e)}"

    def _resolve_cli_executable(self):
        executable = str(self.client or "").strip()
        if not executable:
            return ""
        has_sep = os.path.sep in executable or (os.path.altsep and os.path.altsep in executable)
        if os.path.isabs(executable) or has_sep:
            return executable if os.path.exists(executable) else ""
        return shutil.which(executable) or ""

    def _prompt_to_text(self, prompt):
        if isinstance(prompt, list):
            lines = []
            for item in prompt:
                role = str(item.get("role", "user")).upper()
                content = str(item.get("content", "") or "")
                if content:
                    lines.append("%s:\n%s" % (role, content))
            return "\n\n".join(lines)
        return str(prompt or "")

    def _query_signed_in_cli(
        self, prompt, request_cancelled=None, timeout=None, status_callback=None,
    ):
        executable = self._resolve_cli_executable()
        if not executable:
            raise ValueError("%s executable not found. Configure the full path in Settings." % self.client)

        prompt_text = self._prompt_to_text(prompt)
        model = str(self.profile.model or "").strip()
        timeout = timeout or self.request_options.timeout_seconds

        instruction = (
            "Answer only the reverse-engineering prompt supplied by Genesect. "
            "Do not call tools, run commands, read files, write files, use MCP, "
            "or inspect the workspace. Return only the answer."
        )
        command = self._signed_in_cli_command(executable, model, instruction)
        cli_input = self._signed_in_cli_input(prompt_text, instruction)

        if request_cancelled and request_cancelled():
            return ""

        try:
            result = run_cli_command(
                command,
                cli_input,
                timeout=max(10, int(timeout)),
                cancel_checker=request_cancelled,
                status_callback=status_callback,
            )
        except subprocess.TimeoutExpired:
            hint = ""
            if self.profile.name == "GeminiCLI":
                hint = (
                    " Genesect cannot display Gemini's interactive login. Run `gemini` "
                    "in a terminal, finish sign-in and folder trust, then use Test Connection."
                )
            raise RuntimeError(
                "%s did not finish within %s seconds.%s" % (
                    self.profile.name, max(10, int(timeout)), hint,
                )
            )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if result.returncode != 0:
            detail = stderr or stdout or "no output"
            if self.profile.name == "GeminiCLI":
                raise RuntimeError(self._format_gemini_error(detail))
            raise RuntimeError("%s exited with code %s: %s" % (self.profile.name, result.returncode, detail))
        if self.profile.name == "AntigravityCLI":
            return self._parse_antigravity_output(stdout, stderr)
        if self.profile.name == "GeminiCLI":
            return self._parse_gemini_output(stdout, stderr)
        if not stdout and stderr:
            raise RuntimeError("%s returned no answer. Diagnostic output: %s" % (self.profile.name, stderr))
        return stdout or stderr

    def _parse_gemini_output(self, stdout, stderr):
        payload = None
        if stdout:
            try:
                payload = json.loads(stdout)
            except ValueError:
                start = stdout.find("{")
                end = stdout.rfind("}")
                if start >= 0 and end > start:
                    try:
                        payload = json.loads(stdout[start:end + 1])
                    except ValueError:
                        payload = None

        if isinstance(payload, dict):
            response = payload.get("response")
            error = payload.get("error")
            if response is not None and str(response).strip():
                return str(response).strip()
            if error:
                detail = json.dumps(error, ensure_ascii=False) if isinstance(error, (dict, list)) else str(error)
                raise RuntimeError(self._format_gemini_error(detail))
            raise RuntimeError("GeminiCLI returned JSON without a response.")

        if stdout:
            # Compatibility with Gemini CLI versions that predate JSON output.
            return stdout
        if stderr:
            raise RuntimeError(self._format_gemini_error(stderr))
        raise RuntimeError("GeminiCLI exited successfully but returned no answer.")

    def _format_gemini_error(self, message):
        message = str(message or "").strip() or "no diagnostic output"
        normalized = message.lower()
        auth_or_trust = any(marker in normalized for marker in (
            "auth", "login", "log in", "sign in", "oauth", "credential",
            "trust this folder", "folder trust", "trusted folder",
        ))
        if auth_or_trust:
            return (
                "GeminiCLI needs interactive authentication or folder confirmation. "
                "Genesect only uses Gemini's existing signed-in session and cannot show "
                "that terminal UI. Run `gemini` in a terminal, complete sign-in/trust, "
                "exit Gemini, then retry Test Connection. Raw Gemini message: %s"
            ) % message
        return "GeminiCLI returned an error: %s" % message

    def _parse_antigravity_output(self, stdout, stderr):
        combined = "\n".join(part for part in (stdout, stderr) if part).strip()
        if stdout:
            stream_response = ""
            stream_result = None
            saw_stream_event = False
            for line in stdout.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict) or "event" not in event:
                    continue
                saw_stream_event = True
                if event.get("event") == "step_update":
                    update = event.get("step_update") or {}
                    if isinstance(update, dict) and update.get("step_type") == "agent_response":
                        stream_response += str(update.get("text_delta") or "")
                elif event.get("event") == "result":
                    stream_result = event.get("result")

            if isinstance(stream_result, dict):
                response = stream_result.get("response")
                error = stream_result.get("error")
                status = str(stream_result.get("status") or "").upper()
                if response:
                    return str(response).strip()
                if status == "SUCCESS" and stream_response.strip():
                    return stream_response.strip()
                if status == "SUCCESS":
                    raise RuntimeError("AntigravityCLI reported success but returned no response.")
                raise RuntimeError(self._format_antigravity_error(error or combined or status))
            if saw_stream_event and stream_response.strip():
                return stream_response.strip()

            try:
                payload = json.loads(stdout)
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                response = payload.get("response")
                error = payload.get("error")
                status = str(payload.get("status") or "").upper()
                if response:
                    return str(response).strip()
                if status == "SUCCESS":
                    raise RuntimeError("AntigravityCLI reported success but returned no response.")
                if status and status != "SUCCESS":
                    raise RuntimeError(self._format_antigravity_error(error or combined or status))
                if error:
                    raise RuntimeError(self._format_antigravity_error(error))
                raise RuntimeError(self._format_antigravity_error(combined))

        if self._is_antigravity_permission_error(combined):
            raise RuntimeError(self._format_antigravity_error(combined))
        if stdout:
            return stdout
        if stderr:
            raise RuntimeError(self._format_antigravity_error(stderr))
        raise RuntimeError("AntigravityCLI returned no answer.")

    def _signed_in_cli_input(self, prompt_text, instruction):
        if self.profile.name != "AntigravityCLI":
            return prompt_text
        content = "%s\n\nPROMPT FROM IDA:\n%s" % (instruction, prompt_text)
        return json.dumps({
            "event": "user",
            "message": {"content": content},
        }, ensure_ascii=False) + "\n"

    def _is_antigravity_permission_error(self, message):
        text = str(message or "").lower()
        return (
            "headless mode cannot prompt" in text
            or "auto-denied" in text
            or 'required the "command" permission' in text
            or "permissions.allow" in text
        )

    def _format_antigravity_error(self, message):
        message = str(message or "").strip() or "no diagnostic output"
        if self._is_antigravity_permission_error(message):
            return (
                "Antigravity headless mode tried to use a tool that requires permission, "
                "but headless mode cannot show an approval prompt. Genesect already sends "
                "the IDA context in the prompt, so Antigravity should answer without tools. "
                "If this model still requires a command tool, add a scoped allow rule under "
                "~/.gemini/antigravity-cli/settings.json -> permissions.allow, or choose a "
                "different signed-in/API provider. Avoid --dangerously-skip-permissions for "
                "IDA analysis unless you fully trust the prompt. Raw Antigravity message: %s"
            ) % message
        return "AntigravityCLI returned an error: %s" % message

    def _signed_in_cli_command(self, executable, model, instruction):
        provider = self.profile.name
        model = str(model or "").strip()
        profile_or_provider = str(self.profile.url or "").strip()
        has_model = bool(model and model.lower() != "default")
        if provider == "CodexCLI":
            command = [executable, "exec", "-"]
            if has_model:
                command.extend(["--model", model])
            if profile_or_provider:
                command.extend(["--profile", profile_or_provider])
            return command
        if provider == "ClaudeCode":
            command = [executable, "-p"]
            if has_model:
                command.extend(["--model", model])
            command.append(instruction)
            return command
        if provider == "AntigravityCLI":
            command = [
                executable,
                "--input-format", "stream-json",
                "--output-format", "stream-json",
                "--disable-slash-commands",
            ]
            if has_model:
                command.extend(["--model", model])
            return command
        if provider == "GeminiCLI":
            command = [
                executable, "-p", instruction,
                "--output-format", "json",
                "--skip-trust",
            ]
            if has_model:
                command.extend(["--model", model])
            return command
        if provider == "QwenCode":
            command = [executable, "--prompt", instruction]
            if has_model:
                command.extend(["--model", model])
            return command
        if provider == "OpenCode":
            command = [executable, "run"]
            if has_model:
                command.extend(["--model", model])
            command.append(instruction)
            return command
        if provider == "HermesCLI":
            command = [executable, "--query", instruction]
            if has_model:
                command.extend(["--model", model])
            return command
        return [executable, instruction]


# Module-level singleton
AI_CLIENT = None


def reload_ai_client(config):
    """Atomically rebuild the shared client from the latest saved settings.

    Construct the replacement before publishing it so a setup exception cannot
    discard a working session client. Existing in-flight requests retain their
    local reference to the old instance; subsequent requests use the new one.
    """
    global AI_CLIENT
    replacement = SimpleAI(config)
    AI_CLIENT = replacement
    LOGGER.log(
        "AI runtime refreshed: %s (model: %s)"
        % (replacement.profile.name, replacement.profile.model)
    )
    return replacement
