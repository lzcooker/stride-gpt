#main.py

import base64
import streamlit as st
import streamlit.components.v1 as components
from github import Github
from collections import defaultdict
import re
import os
from dotenv import load_dotenv
from openai import OpenAI
import requests
import json
import tiktoken

from i18n import get_text, get_prompt_language_suffix
from threat_model import (
    create_threat_model_prompt,
    get_threat_model,
    get_threat_model_azure,
    get_threat_model_google,
    get_threat_model_mistral,
    get_threat_model_ollama,
    get_threat_model_anthropic,
    get_threat_model_lm_studio,
    get_threat_model_groq,
    get_threat_model_glm,
    get_threat_model_ecloud,
    json_to_markdown,
    get_image_analysis,
    get_image_analysis_azure,
    get_image_analysis_google,
    get_image_analysis_anthropic,
    get_image_analysis_glm,
    create_image_analysis_prompt,
)
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure, get_attack_tree_mistral, get_attack_tree_ollama, get_attack_tree_anthropic, get_attack_tree_lm_studio, get_attack_tree_groq, get_attack_tree_google, get_attack_tree_glm, get_attack_tree_ecloud
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google, get_mitigations_mistral, get_mitigations_ollama, get_mitigations_anthropic, get_mitigations_lm_studio, get_mitigations_groq, get_mitigations_glm, get_mitigations_ecloud
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google, get_test_cases_mistral, get_test_cases_ollama, get_test_cases_anthropic, get_test_cases_lm_studio, get_test_cases_groq, get_test_cases_glm, get_test_cases_ecloud
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, get_dread_assessment_mistral, get_dread_assessment_ollama, get_dread_assessment_anthropic, get_dread_assessment_lm_studio, get_dread_assessment_groq, get_dread_assessment_glm, get_dread_assessment_ecloud, dread_json_to_markdown

# ------------------ Helper Functions ------------------ #

# Function to get available models from LM Studio Server
def get_lm_studio_models(endpoint):
    try:
        client = OpenAI(
            base_url=f"{endpoint}/v1",
            api_key="not-needed"
        )
        models = client.models.list()
        return [model.id for model in models.data]
    except requests.exceptions.ConnectionError:
        st.error(get_text("lm_studio_connect_error", st.session_state.language))
        return ["local-model"]
    except Exception as e:
        st.error(get_text("lm_studio_fetch_error", st.session_state.language).format(str(e)))
        return ["local-model"]

def get_ollama_models(ollama_endpoint):
    """
    Get list of available models from Ollama.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        
    Returns:
        list: List of available model names
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/tags"
    
    try:
        response = requests.get(url, timeout=10)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        models_data = response.json()
        
        # Extract model names from the response
        model_names = [model['name'] for model in models_data['models']]
        if not model_names:
            st.warning(get_text("ollama_no_models_error", st.session_state.language))
            return ["local-model"]
        return model_names
            
    except requests.exceptions.ConnectionError:
        st.error(get_text("ollama_connect_error", st.session_state.language))
        return ["local-model"]
    except requests.exceptions.Timeout:
        st.error(get_text("ollama_timeout_error", st.session_state.language))
        return ["local-model"]
    except (KeyError, json.JSONDecodeError):
        st.error(get_text("ollama_invalid_response_error", st.session_state.language))
        return ["local-model"]
    except Exception as e:
        st.error(get_text("ollama_unexpected_error", st.session_state.language).format(str(e)))
        return ["local-model"]

# Function to get user input for the application description and key details
def get_input():
    # Repository type selection
    repo_type = st.selectbox(
        label=get_text("repo_type_label", st.session_state.language),
        options=["github", "gerrit"],
        format_func=lambda x: get_text(f"repo_type_{x}", st.session_state.language),
        key="repo_type"
    )

    # GitHub URL input
    github_url = ""
    gerrit_url = ""

    if repo_type == "github":
        github_url = st.text_input(
            label=get_text("github_url_label", st.session_state.language),
            placeholder="https://github.com/owner/repo",
            key="github_url",
            help=get_text("github_url_help", st.session_state.language),
        )

        if github_url and github_url != st.session_state.get('last_analyzed_url', ''):
            if 'github_api_key' not in st.session_state or not st.session_state['github_api_key']:
                st.warning(get_text("github_api_key_warning", st.session_state.language))
            else:
                with st.spinner(get_text("analyzing_github_repo", st.session_state.language)):
                    system_description = analyze_github_repo(github_url)
                    st.session_state['github_analysis'] = system_description
                    st.session_state['last_analyzed_url'] = github_url
                    st.session_state['app_input'] = system_description + "\n\n" + st.session_state.get('app_input', '')

    # Gerrit URL input
    elif repo_type == "gerrit":
        gerrit_url = st.text_input(
            label=get_text("gerrit_url_label", st.session_state.language),
            placeholder="https://gerrit.example.com/project/repo",
            key="gerrit_url",
            help=get_text("gerrit_url_help", st.session_state.language),
        )

        if gerrit_url and gerrit_url != st.session_state.get('last_analyzed_url', ''):
            gerrit_username = st.session_state.get('gerrit_username', '')
            gerrit_password = st.session_state.get('gerrit_password', '')

            if not gerrit_username or not gerrit_password:
                st.warning(get_text("gerrit_api_key_warning", st.session_state.language))
            else:
                with st.spinner(get_text("analyzing_gerrit_repo", st.session_state.language)):
                    system_description = analyze_gerrit_repo(gerrit_url)
                    st.session_state['gerrit_analysis'] = system_description
                    st.session_state['last_analyzed_url'] = gerrit_url
                    st.session_state['app_input'] = system_description + "\n\n" + st.session_state.get('app_input', '')

    input_text = st.text_area(
        label=get_text("app_input_label", st.session_state.language),
        value=st.session_state.get('app_input', ''),
        placeholder=get_text("app_input_placeholder", st.session_state.language),
        height=300,
        key="app_desc",
        help=get_text("app_input_help", st.session_state.language),
    )

    st.session_state['app_input'] = input_text

    return input_text

def estimate_tokens(text, model="gpt-4o"):
    """
    Estimate the number of tokens in a text string.
    Uses tiktoken for OpenAI models, or falls back to a character-based approximation.
    
    Args:
        text: The text to estimate tokens for
        model: The model to use for estimation (default: gpt-4o)
        
    Returns:
        Estimated token count
    """
    try:
        # Try to use tiktoken for accurate estimation
        enc = tiktoken.encoding_for_model(model)
        return len(enc.encode(text))
    except (ImportError, KeyError, ValueError):
        # Fall back to character-based approximation
        # Different languages have different token densities
        # English: ~4 chars per token, Chinese: ~1-2 chars per token
        return len(text) // 4  # Conservative estimate for English text

def analyze_github_repo(repo_url):
    # Extract owner and repo name from URL
    parts = repo_url.split('/')
    owner = parts[-2]
    repo_name = parts[-1]

    # Initialize PyGithub
    g = Github(st.session_state.get('github_api_key', ''))

    # Get the repository
    repo = g.get_repo(f"{owner}/{repo_name}")
    # Get the default branch
    default_branch = repo.default_branch

    # Get the tree of the default branch
    tree = repo.get_git_tree(default_branch, recursive=True)

    # Analyze files
    file_summaries = defaultdict(list)
    total_tokens = 0
    
    # Get the configured token limit from session state, or use a default
    token_limit = st.session_state.get('token_limit', 64000)
    
    # Get the selected model for token estimation
    model_provider = st.session_state.get('model_provider', 'OpenAI API')
    selected_model = st.session_state.get('selected_model', 'gpt-4o')
    
    # Determine which model to use for token estimation
    token_estimation_model = "gpt-4o"  # Default fallback
    if model_provider == "OpenAI API":
        token_estimation_model = selected_model
    
    # Reserve some tokens for the model's response (typically 20-30% of the context window)
    # This ensures the model has enough space to generate a response
    analysis_token_limit = int(token_limit * 0.7)
    
    # Progress bar for GitHub analysis
    progress_bar = st.progress(0)
    status_text = st.empty()
    status_text.text("Analyzing repository structure...")
    
    # First, get the README to prioritize it
    readme_content = ""
    readme_tokens = 0
    try:
        readme_file = repo.get_contents("README.md", ref=default_branch)
        readme_content = base64.b64decode(readme_file.content).decode()
        readme_tokens = estimate_tokens(readme_content, token_estimation_model)
    except:
        try:
            # Try lowercase readme.md as fallback
            readme_file = repo.get_contents("readme.md", ref=default_branch)
            readme_content = base64.b64decode(readme_file.content).decode()
            readme_tokens = estimate_tokens(readme_content, token_estimation_model)
        except:
            st.warning("No README.md found in the repository.")
    
    # Calculate how many tokens we can use for code analysis
    # Reserve at least 30% of the token limit for code analysis
    code_token_limit = max(int(analysis_token_limit * 0.3), analysis_token_limit - readme_tokens)
    
    # If README is too large, truncate it
    if readme_tokens > analysis_token_limit * 0.7:
        # Truncate README to 70% of the analysis token limit
        truncation_ratio = (analysis_token_limit * 0.7) / readme_tokens
        max_readme_chars = int(len(readme_content) * truncation_ratio)
        readme_content = readme_content[:max_readme_chars] + "...\n(README truncated due to length)\n\n"
        readme_tokens = estimate_tokens(readme_content, token_estimation_model)
    
    # Update progress
    progress_bar.progress(0.2)
    status_text.text("Analyzing code files...")
    
    # Get all code files
    code_files = [file for file in tree.tree if file.type == "blob" and file.path.endswith(
        ('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb', '.c', '.cpp', '.h', '.cs', '.php')
    )]
    
    # Sort files by importance (you can customize this logic)
    # For example, prioritize main files, configuration files, etc.
    def file_importance(file):
        # Lower score means higher importance
        if file.path.lower() in ['main.py', 'app.py', 'index.js', 'package.json', 'config.json']:
            return 0
        if 'test' in file.path.lower() or 'spec' in file.path.lower():
            return 3
        if file.path.endswith(('.py', '.js', '.ts', '.java', '.go')):
            return 1
        return 2
    
    code_files.sort(key=file_importance)
    
    # Process files until we reach the token limit
    total_tokens = readme_tokens
    file_count = len(code_files)
    processed_files = 0
    
    for i, file in enumerate(code_files):
        # Update progress
        progress_percent = 0.2 + (0.8 * (i / file_count))
        progress_bar.progress(min(progress_percent, 1.0))
        status_text.text(f"Analyzing file {i+1}/{file_count}: {file.path}")
        
        try:
            content = repo.get_contents(file.path, ref=default_branch)
            decoded_content = base64.b64decode(content.content).decode()
            
            # Summarize the file content
            summary = summarize_file(file.path, decoded_content)
            summary_tokens = estimate_tokens(summary, token_estimation_model)
            
            # Check if adding this summary would exceed our token limit
            if total_tokens + summary_tokens > analysis_token_limit:
                # If we're about to exceed the limit, add a note and stop processing
                file_summaries["info"].append(f"Analysis truncated: {file_count - i} more files not analyzed due to token limit.")
                break
            
            file_summaries[file.path.split('.')[-1]].append(summary)
            total_tokens += summary_tokens
            processed_files += 1
        except Exception as e:
            # Skip files that can't be decoded
            continue
    
    # Clear progress indicators
    progress_bar.empty()
    status_text.empty()
    
    # Compile the analysis into a system description
    system_description = f"Repository: {repo_url}\n\n"
    
    if readme_content:
        system_description += "README.md Content:\n"
        system_description += readme_content + "\n\n"

    for file_type, summaries in file_summaries.items():
        system_description += f"{file_type.upper()} Files:\n"
        for summary in summaries:
            system_description += summary + "\n"
        system_description += "\n"
    
    # Add token usage information
    estimated_total_tokens = estimate_tokens(system_description, token_estimation_model)
    system_description += f"\nRepository Analysis Summary:\n"
    system_description += f"- Files analyzed: {processed_files} of {file_count} total files\n"
    system_description += f"- Token usage estimate: ~{estimated_total_tokens} tokens\n"
    system_description += f"- Token limit configured: {token_limit} tokens\n"
    
    # Show a warning if we're close to the token limit
    if estimated_total_tokens > token_limit * 0.9:
        st.warning(f"⚠️ The GitHub analysis is using approximately {estimated_total_tokens} tokens, which is close to your configured limit of {token_limit}. Consider increasing the token limit in the sidebar settings if you need more comprehensive analysis.")
    
    return system_description

def analyze_gerrit_repo(repo_url):
    """
    Analyze a Gerrit repository to extract system description information.

    Args:
        repo_url: URL of the Gerrit repository

    Returns:
        String containing system description based on repository analysis
    """
    import base64
    from urllib.parse import urlparse

    try:
        # Parse the Gerrit repository URL
        parsed_url = urlparse(repo_url)
        gerrit_host = parsed_url.netloc
        repo_path = parsed_url.path.strip('/')

        # Basic URL validation
        if not gerrit_host or not repo_path:
            raise ValueError("无效的Gerrit URL格式")

        # Extract project name (remove /a/ prefix if present for anonymous access)
        if repo_path.startswith('a/'):
            repo_path = repo_path[2:]

        # Build Gerrit API URL
        gerrit_api_url = f"https://{gerrit_host}/projects/{repo_path}"

        # Get authentication credentials
        username = st.session_state.get('gerrit_username', '')
        password = st.session_state.get('gerrit_password', '')

        # Setup authentication
        auth = None
        if username and password:
            auth = (username, password)

        # Get project information
        headers = {'Accept': 'application/json'}
        response = requests.get(gerrit_api_url, auth=auth, headers=headers, timeout=30)

        # Gerrit returns JSON with a magic prefix, remove it
        if response.status_code == 200:
            content = response.text
            if content.startswith(")]}'\n"):
                content = content[5:]
            project_info = json.loads(content)
        else:
            raise Exception(f"Failed to access Gerrit project: {response.status_code}")

        # Get the configured token limit from session state
        token_limit = st.session_state.get('gerrit_token_limit', 64000)

        # Get the selected model for token estimation
        model_provider = st.session_state.get('model_provider', 'OpenAI API')
        selected_model = st.session_state.get('selected_model', 'gpt-4o')

        # Determine which model to use for token estimation
        token_estimation_model = "gpt-4o"  # Default fallback
        if model_provider == "OpenAI API":
            token_estimation_model = selected_model

        # Reserve some tokens for the model's response
        analysis_token_limit = int(token_limit * 0.7)

        # Progress bar for Gerrit analysis
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_text.text("Analyzing Gerrit repository structure...")

        # Initialize variables
        file_summaries = defaultdict(list)
        total_tokens = 0

        # Try to get README content first
        readme_content = ""
        readme_tokens = 0
        try:
            # Try to get files from the repository
            files_api_url = f"https://{gerrit_host}/projects/{repo_path}/files/?recursive&limit=100"
            files_response = requests.get(files_api_url, auth=auth, headers=headers, timeout=30)

            if files_response.status_code == 200:
                files_content = files_response.text
                if files_content.startswith(")]}'\n"):
                    files_content = files_content[5:]
                files_data = json.loads(files_content)

                # Look for README files
                for file_path in files_data:
                    if 'README' in file_path.upper():
                        print(f"Found README file: {file_path}")
                        file_api_url = f"https://{gerrit_host}/projects/{repo_path}/files/{file_path}/content"
                        file_response = requests.get(file_api_url, auth=auth, headers=headers, timeout=30)

                        if file_response.status_code == 200:
                            file_content_b64 = file_response.text
                            if file_content_b64.startswith(")]}'\n"):
                                file_content_b64 = file_content_b64[5:]
                            # Decode base64 content
                            readme_content = base64.b64decode(file_content_b64).decode()
                            readme_tokens = estimate_tokens(readme_content, token_estimation_model)
                            break
        except Exception as e:
            st.warning(f"Could not fetch README from Gerrit repository: {str(e)}")

        # Calculate how many tokens we can use for code analysis
        code_token_limit = max(int(analysis_token_limit * 0.3), analysis_token_limit - readme_tokens)

        # If README is too large, truncate it
        if readme_tokens > analysis_token_limit * 0.7:
            truncation_ratio = (analysis_token_limit * 0.7) / readme_tokens
            max_readme_chars = int(len(readme_content) * truncation_ratio)
            readme_content = readme_content[:max_readme_chars] + "...\n(README truncated due to length)\n\n"
            readme_tokens = estimate_tokens(readme_content, token_estimation_model)

        # Update progress
        progress_bar.progress(0.2)
        status_text.text("Analyzing code files...")

        # Try to get code files for analysis
        try:
            if files_response.status_code == 200:
                # Filter code files
                code_files = [file_path for file_path in files_data if file_path.endswith(
                    ('.py', '.js', '.ts', '.html', '.css', '.java', '.go', '.rb', '.c', '.cpp', '.h', '.cs', '.php')
                )]

                # Sort files by importance (similar to GitHub analysis)
                def file_importance(file_path):
                    if file_path.lower() in ['main.py', 'app.py', 'index.js', 'package.json', 'config.json']:
                        return 0
                    if 'test' in file_path.lower() or 'spec' in file_path.lower():
                        return 3
                    if file_path.endswith(('.py', '.js', '.ts', '.java', '.go')):
                        return 1
                    return 2

                code_files.sort(key=file_importance)

                # Process files until we reach the token limit
                total_tokens = readme_tokens
                file_count = len(code_files)
                processed_files = 0

                for i, file_path in enumerate(code_files):
                    # Update progress
                    progress_percent = 0.2 + (0.8 * (i / file_count))
                    progress_bar.progress(min(progress_percent, 1.0))
                    status_text.text(f"Analyzing file {i+1}/{file_count}: {file_path}")

                    try:
                        file_api_url = f"https://{gerrit_host}/projects/{repo_path}/files/{file_path}/content"
                        file_response = requests.get(file_api_url, auth=auth, headers=headers, timeout=30)

                        if file_response.status_code == 200:
                            file_content_b64 = file_response.text
                            if file_content_b64.startswith(")]}'\n"):
                                file_content_b64 = file_content_b64[5:]
                            decoded_content = base64.b64decode(file_content_b64).decode()

                            # Summarize the file content
                            summary = summarize_file(file_path, decoded_content)
                            summary_tokens = estimate_tokens(summary, token_estimation_model)

                            # Check if adding this summary would exceed our token limit
                            if total_tokens + summary_tokens > analysis_token_limit:
                                file_summaries["info"].append(f"Analysis truncated: {file_count - i} more files not analyzed due to token limit.")
                                break

                            file_summaries[file_path.split('.')[-1]].append(summary)
                            total_tokens += summary_tokens
                            processed_files += 1
                    except Exception as e:
                        # Skip files that can't be accessed
                        continue
        except Exception as e:
            st.warning(f"Could not analyze code files from Gerrit repository: {str(e)}")

        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()

        # Compile the analysis into a system description
        system_description = f"Gerrit Repository: {repo_url}\n\n"

        if readme_content:
            system_description += "README Content:\n"
            system_description += readme_content + "\n\n"

        for file_type, summaries in file_summaries.items():
            system_description += f"{file_type.upper()} Files:\n"
            for summary in summaries:
                system_description += summary + "\n"
            system_description += "\n"

        # Add token usage information
        estimated_total_tokens = estimate_tokens(system_description, token_estimation_model)
        system_description += f"\nRepository Analysis Summary:\n"
        system_description += f"- Files analyzed: {processed_files} of {file_count if 'file_count' in locals() else 0} total files\n"
        system_description += f"- Token usage estimate: ~{estimated_total_tokens} tokens\n"
        system_description += f"- Token limit configured: {token_limit} tokens\n"

        # Show a warning if we're close to the token limit
        if estimated_total_tokens > token_limit * 0.9:
            st.warning(f"⚠️ The Gerrit analysis is using approximately {estimated_total_tokens} tokens, which is close to your configured limit of {token_limit}. Consider increasing the token limit in the sidebar settings if you need more comprehensive analysis.")

        return system_description

    except requests.exceptions.Timeout:
        error_msg = "连接Gerrit服务器超时。请检查网络连接或服务器状态。"
        st.error(error_msg)
        return f"错误: {error_msg}"
    except requests.exceptions.ConnectionError:
        error_msg = "无法连接到Gerrit服务器。请检查URL和网络连接。"
        st.error(error_msg)
        return f"错误: {error_msg}"
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            error_msg = "Gerrit认证失败。请检查用户名和密码。"
        elif e.response.status_code == 403:
            error_msg = "Gerrit访问被拒绝。请检查权限设置。"
        elif e.response.status_code == 404:
            error_msg = "Gerrit项目不存在。请检查项目路径。"
        else:
            error_msg = f"Gerrit HTTP错误: {e.response.status_code}"
        st.error(error_msg)
        return f"错误: {error_msg}"
    except Exception as e:
        error_msg = f"分析Gerrit仓库时出错: {str(e)}"
        st.error(error_msg)
        return f"错误: {error_msg}"

def summarize_file(file_path, content):
    """
    Summarize a file's content by extracting key components.
    Adapts the level of detail based on file size and importance.
    
    Args:
        file_path: Path to the file
        content: Content of the file
        
    Returns:
        A string summary of the file
    """
    # Determine file type
    file_ext = file_path.split('.')[-1].lower() if '.' in file_path else ''
    
    # Initialize summary
    summary = f"File: {file_path}\n"
    
    # For very large files, be more selective
    is_large_file = len(content) > 10000
    
    # Extract imports based on file type
    imports = []
    if file_ext in ['py']:
        imports = re.findall(r'^import .*|^from .* import .*', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        imports = re.findall(r'^import .*|^const .* = require\(.*\)|^import .* from .*', content, re.MULTILINE)
    elif file_ext in ['java']:
        imports = re.findall(r'^import .*;', content, re.MULTILINE)
    elif file_ext in ['go']:
        imports = re.findall(r'^import \(.*?\)|^import ".*"', content, re.MULTILINE | re.DOTALL)
    
    # Extract functions based on file type
    functions = []
    if file_ext in ['py']:
        functions = re.findall(r'def .*\(.*\):', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        functions = re.findall(r'function .*\(.*\) {|const .* = \(.*\) =>|.*: function\(.*\)', content, re.MULTILINE)
    elif file_ext in ['java', 'c', 'cpp', 'cs']:
        functions = re.findall(r'(public|private|protected|static|\s) +[\w\<\>\[\]]+\s+(\w+) *\([^\)]*\) *(\{?|[^;])', content, re.MULTILINE)
        functions = [' '.join(f).strip() for f in functions]
    elif file_ext in ['go']:
        functions = re.findall(r'func .*\(.*\).*{', content, re.MULTILINE)
    
    # Extract classes based on file type
    classes = []
    if file_ext in ['py']:
        classes = re.findall(r'class .*:', content, re.MULTILINE)
    elif file_ext in ['js', 'ts']:
        classes = re.findall(r'class .* {', content, re.MULTILINE)
    elif file_ext in ['java', 'c', 'cpp', 'cs']:
        classes = re.findall(r'(public|private|protected|static|\s) +(class|interface) +(\w+)', content, re.MULTILINE)
        classes = [' '.join(c).strip() for c in classes]
    
    # Add imports to summary (limit based on file size)
    import_limit = 5 if not is_large_file else 3
    if imports:
        summary += "Imports:\n" + "\n".join(imports[:import_limit])
        if len(imports) > import_limit:
            summary += f"\n... ({len(imports) - import_limit} more imports)"
        summary += "\n"
    
    # Add classes to summary (limit based on file size)
    class_limit = 5 if not is_large_file else 3
    if classes:
        summary += "Classes:\n" + "\n".join(classes[:class_limit])
        if len(classes) > class_limit:
            summary += f"\n... ({len(classes) - class_limit} more classes)"
        summary += "\n"
    
    # Add functions to summary (limit based on file size)
    function_limit = 10 if not is_large_file else 5
    if functions:
        summary += "Functions:\n" + "\n".join(functions[:function_limit])
        if len(functions) > function_limit:
            summary += f"\n... ({len(functions) - function_limit} more functions)"
        summary += "\n"
    
    # For configuration files (JSON, YAML, etc.), try to extract key information
    if file_ext in ['json', 'yaml', 'yml', 'toml', 'ini']:
        # Just include a snippet of the beginning for config files
        config_preview = content[:500] + ("..." if len(content) > 500 else "")
        summary += "Configuration Content Preview:\n" + config_preview + "\n"
    
    # For README or documentation files, include a brief excerpt
    if 'readme' in file_path.lower() or file_ext in ['md', 'rst', 'txt']:
        doc_preview = content[:300] + ("..." if len(content) > 300 else "")
        summary += "Content Preview:\n" + doc_preview + "\n"
    
    return summary

# Function to render Mermaid diagram
def mermaid(code: str, height: int = 500) -> None:
    """
    Render a Mermaid diagram with error handling.
    If rendering fails, displays the raw code with an error message.
    """
    # Clean the code first
    from utils import clean_mermaid_syntax
    cleaned_code = clean_mermaid_syntax(code)

    # Create a unique ID for this diagram
    import hashlib
    diagram_id = f"mermaid-{hashlib.md5(cleaned_code.encode()).hexdigest()[:8]}"

    components.html(
        f"""
        <div style="margin: 20px 0;">
            <h4 style="margin-bottom: 10px;">Attack Tree Diagram:</h4>
            <div id="mermaid-container-{diagram_id}" style="border: 1px solid #ddd; border-radius: 5px; padding: 20px; background-color: white; min-height: {height}px;">
                <div id="mermaid-{diagram_id}" style="display: none;">
                    {cleaned_code}
                </div>
                <div id="mermaid-loading-{diagram_id}" style="text-align: center; padding: 50px;">
                    <div style="color: #666;">Loading diagram...</div>
                </div>
                <div id="mermaid-error-{diagram_id}" style="display: none; padding: 20px; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px;">
                    <h4 style="color: #721c24; margin-top: 0;">Mermaid Rendering Error</h4>
                    <p style="color: #721c24; margin-bottom: 15px;">Unable to render the diagram. Please check the browser console for details.</p>
                    <details style="margin-top: 15px;">
                        <summary style="cursor: pointer; color: #0066cc;">View raw mermaid code</summary>
                        <pre style="background-color: #f1f3f4; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 10px;"><code>{cleaned_code}</code></pre>
                    </details>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/mermaid@8.14.0/dist/mermaid.min.js"></script>
        <script>
            // Initialize mermaid
            mermaid.initialize({{
                startOnLoad: false,
                theme: 'default',
                flowchart: {{
                    useMaxWidth: false,
                    htmlLabels: true,
                    curve: 'basis'
                }},
                securityLevel: 'loose'
            }});

            // Function to render the diagram
            function renderMermaidDiagram() {{
                try {{
                    const diagramElement = document.getElementById('mermaid-{diagram_id}');
                    const loadingElement = document.getElementById('mermaid-loading-{diagram_id}');
                    const errorElement = document.getElementById('mermaid-error-{diagram_id}');
                    const containerElement = document.getElementById('mermaid-container-{diagram_id}');

                    if (diagramElement && loadingElement) {{
                        // Hide loading, show diagram
                        loadingElement.style.display = 'none';
                        diagramElement.style.display = 'block';

                        // Render the diagram
                        mermaid.init(undefined, diagramElement);

                        console.log('Mermaid diagram rendered successfully: {diagram_id}');
                    }}
                }} catch (error) {{
                    console.error('Mermaid rendering error:', error);
                    const loadingElement = document.getElementById('mermaid-loading-{diagram_id}');
                    const errorElement = document.getElementById('mermaid-error-{diagram_id}');

                    if (loadingElement && errorElement) {{
                        loadingElement.style.display = 'none';
                        errorElement.style.display = 'block';
                    }}
                }}
            }}

            // Try multiple times to ensure the container is ready
            setTimeout(renderMermaidDiagram, 100);
            setTimeout(renderMermaidDiagram, 500);
            setTimeout(renderMermaidDiagram, 1000);

            // Also try on document ready
            if (document.readyState === 'loading') {{
                document.addEventListener('DOMContentLoaded', renderMermaidDiagram);
            }} else {{
                renderMermaidDiagram();
            }}
        </script>
        """,
        height=height,
    )

def load_env_variables():
    # Try to load from .env file
    if os.path.exists('.env'):
        load_dotenv('.env')
    
    # Load GitHub API key from environment variable
    github_api_key = os.getenv('GITHUB_API_KEY')
    if github_api_key:
        st.session_state['github_api_key'] = github_api_key

    # Load other API keys if needed
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if openai_api_key:
        st.session_state['openai_api_key'] = openai_api_key

    anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
    if anthropic_api_key:
        st.session_state['anthropic_api_key'] = anthropic_api_key

    azure_api_key = os.getenv('AZURE_API_KEY')
    if azure_api_key:
        st.session_state['azure_api_key'] = azure_api_key

    azure_api_endpoint = os.getenv('AZURE_API_ENDPOINT')
    if azure_api_endpoint:
        st.session_state['azure_api_endpoint'] = azure_api_endpoint

    azure_deployment_name = os.getenv('AZURE_DEPLOYMENT_NAME')
    if azure_deployment_name:
        st.session_state['azure_deployment_name'] = azure_deployment_name

    google_api_key = os.getenv('GOOGLE_API_KEY')
    if google_api_key:
        st.session_state['google_api_key'] = google_api_key

    mistral_api_key = os.getenv('MISTRAL_API_KEY')
    if mistral_api_key:
        st.session_state['mistral_api_key'] = mistral_api_key

    groq_api_key = os.getenv('GROQ_API_KEY')
    if groq_api_key:
        st.session_state['groq_api_key'] = groq_api_key

    glm_api_key = os.getenv('GLM_API_KEY')
    if glm_api_key:
        st.session_state['glm_api_key'] = glm_api_key

    ecloud_api_key = os.getenv('ECLOUD_API_KEY')
    if ecloud_api_key:
        st.session_state['ecloud_api_key'] = ecloud_api_key

    # Add Ollama endpoint configuration
    ollama_endpoint = os.getenv('OLLAMA_ENDPOINT', 'http://localhost:11434')
    st.session_state['ollama_endpoint'] = ollama_endpoint

    # Add LM Studio Server endpoint configuration
    lm_studio_endpoint = os.getenv('LM_STUDIO_ENDPOINT', 'http://localhost:1234')
    st.session_state['lm_studio_endpoint'] = lm_studio_endpoint

# Call this function at the start of your app
load_env_variables()

# ------------------ Model Token Limits ------------------ #

# Define token limits for specific model+provider combinations
# Format: {"provider:model": {"default": default_value, "max": max_value}}
model_token_limits = {
    # OpenAI models
    "OpenAI API:gpt-4.5-preview": {"default": 64000, "max": 128000},
    "OpenAI API:gpt-4.1": {"default": 128000, "max": 1000000},  # 1M tokens context
    "OpenAI API:gpt-4o": {"default": 64000, "max": 128000},
    "OpenAI API:gpt-4o-mini": {"default": 64000, "max": 128000},
    "OpenAI API:o1": {"default": 64000, "max": 200000},
    "OpenAI API:o3": {"default": 64000, "max": 200000},
    "OpenAI API:o3-mini": {"default": 64000, "max": 200000},
    "OpenAI API:o4-mini": {"default": 64000, "max": 200000},  # Increased to 200K based on OpenAI docs
    
    # Claude models
    "Anthropic API:claude-opus-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-sonnet-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-7-sonnet-latest": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-5-haiku-latest": {"default": 64000, "max": 200000},
    
    # Mistral models
    "Mistral API:mistral-large-latest": {"default": 64000, "max": 131000},
    "Mistral API:mistral-small-latest": {"default": 16000, "max": 32000},
    
    # Google models
    "Google AI API:gemini-2.5-pro-preview-05-06": {"default": 200000, "max": 1000000},
    "Google AI API:gemini-2.5-flash-preview-05-20": {"default": 200000, "max": 1000000},
    "Google AI API:gemini-2.0-flash": {"default": 120000, "max": 1000000},
    "Google AI API:gemini-2.0-flash-lite": {"default": 120000, "max": 1000000},
    
    # Groq models
    "Groq API:deepseek-r1-distill-llama-70b": {"default": 64000, "max": 128000},
    "Groq API:llama-3.3-70b-versatile": {"default": 64000, "max": 128000},
    "Groq API:llama-3.1-8b-instant": {"default": 64000, "max": 128000},
    "Groq API:mixtral-8x7b-32768": {"default": 16000, "max": 32000},
    "Groq API:gemma-9b-it": {"default": 4000, "max": 8192},

    # GLM models
    "GLM API:glm-4.5": {"default": 64000, "max": 128000},
    "GLM API:glm-4.5-air": {"default": 64000, "max": 128000},

    # eCloud models
    "eCloud:deepseek-v3": {"default": 64000, "max": 128000},
   
    
    # Azure models - conservative defaults
    "Azure OpenAI Service:default": {"default": 64000, "max": 128000},
    
    # Ollama and LM Studio - conservative defaults
    "Ollama:default": {"default": 8000, "max": 32000},
    "LM Studio Server:default": {"default": 8000, "max": 32000}
}

st.set_page_config(
    page_title="STRIDE GPT",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load custom CSS for black and purple theme
def load_css():
    with open("style.css", "r", encoding="utf-8") as f:
        css = f.read()
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

load_css()

# Initialize session state for language
if "language" not in st.session_state:
    st.session_state.language = "en"

# Define callback for language change
def on_language_change():
    """Update language when user changes selection"""
    st.session_state.language = st.session_state.language_selector

# Define callback for model provider change
def on_model_provider_change():
    """Update token limit and selected model when model provider changes"""
    # Get the new model provider
    new_provider = st.session_state.model_provider
    
    # Set the token limit to the default for the new provider
    provider_key = f"{new_provider}:default"
    if provider_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[provider_key]["default"]
    else:
        # Fallback to a conservative default
        st.session_state.token_limit = 8000
    
    # Reset the current_model_key to force token limit update in Advanced Settings
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key
    
    # Update the selected model based on the new provider
    # This ensures that when provider changes, we reset the model selection
    # which will trigger the on_model_selection_change callback
    if new_provider == "OpenAI API":
        st.session_state.selected_model = "gpt-4o"
    elif new_provider == "Anthropic API":
        st.session_state.selected_model = "claude-sonnet-4-20250514"
    elif new_provider == "Azure OpenAI Service":
        # Use whatever the first Azure model is in your UI
        pass  # Will use the default selected in the UI
    elif new_provider == "Google AI API":
        st.session_state.selected_model = "gemini-2.5-pro-preview-05-06"
    elif new_provider == "Mistral API":
        st.session_state.selected_model = "mistral-large-latest"
    elif new_provider == "Groq API":
        st.session_state.selected_model = "llama-3.3-70b-versatile"
    elif new_provider == "GLM API":
        st.session_state.selected_model = "glm-4.5"
    elif new_provider == "eCloud":
        st.session_state.selected_model = "deepseek-v3"
    # For Ollama and LM Studio, we don't set a default as they depend on locally available models

# Define callback for model selection change
def on_model_selection_change():
    """Update token limit when specific model is selected"""
    # Only proceed if we have both a model provider and a selected model
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return
    
    model_provider = st.session_state.model_provider
    selected_model = st.session_state.selected_model
    
    # Create the key for lookup
    model_key = f"{model_provider}:{selected_model}"
    
    # If we have a specific limit for this model, use it
    if model_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[model_key]["default"]
    else:
        # Otherwise use a provider default
        provider_key = f"{model_provider}:default"
        if provider_key in model_token_limits:
            st.session_state.token_limit = model_token_limits[provider_key]["default"]
    
    # Reset the current_model_key to force token limit update in Advanced Settings
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key

# ------------------ Sidebar ------------------ #

st.sidebar.image("logo.png")

# Language switcher
language = st.sidebar.selectbox(
    get_text("language_label", st.session_state.language),
    ["en", "zh"],
    index=0 if st.session_state.language == "en" else 1,
    key="language_selector",
    on_change=on_language_change,
    format_func=lambda x: get_text("language_option_en") if x == "en" else get_text("language_option_zh")
)

# Update session state language
st.session_state.language = language

# Add instructions on how to use the app to the sidebar
st.sidebar.header(get_text("sidebar_header", st.session_state.language))

with st.sidebar:
    # Add model selection input field to the sidebar
    model_provider = st.selectbox(
        get_text("model_provider_label", st.session_state.language),
        ["GLM API", "eCloud", "OpenAI API", "Anthropic API", "Azure OpenAI Service", "Google AI API", "Mistral API", "Groq API", "Ollama", "LM Studio Server"],
        key="model_provider",
        on_change=on_model_provider_change,
        help=get_text("model_provider_help", st.session_state.language),
    )

    if model_provider == "OpenAI API":
        st.markdown(get_text("openai_instructions", st.session_state.language))
        # Add OpenAI API key input field to the sidebar
        openai_api_key = st.text_input(
            get_text("openai_api_key_label", st.session_state.language),
            value=st.session_state.get('openai_api_key', ''),
            type="password",
            help=get_text("openai_api_key_help", st.session_state.language),
        )
        if openai_api_key:
            st.session_state['openai_api_key'] = openai_api_key

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            get_text("openai_model_label", st.session_state.language),
            ["gpt-4.5-preview", "gpt-4.1", "gpt-4o", "gpt-4o-mini", "o1", "o3", "o3-mini", "o4-mini"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("openai_model_help", st.session_state.language),
        )

    if model_provider == "Anthropic API":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("Anthropic") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add Anthropic API key input field to the sidebar
        anthropic_api_key = st.text_input(
            get_text("anthropic_api_key_label", st.session_state.language),
            value=st.session_state.get('anthropic_api_key', ''),
            type="password",
            help=get_text("anthropic_api_key_help", st.session_state.language),
        )
        if anthropic_api_key:
            st.session_state['anthropic_api_key'] = anthropic_api_key

        # Add model selection input field to the sidebar
        anthropic_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            ["claude-opus-4-20250514", "claude-sonnet-4-20250514", "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest"],
            index=1,  # Make claude-sonnet-4-20250514 the default
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("anthropic_model_help", st.session_state.language)
        )

    if model_provider == "Azure OpenAI Service":
        st.markdown(
        get_text("step_enter_azure_details", st.session_state.language) + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )

        # Add Azure OpenAI API key input field to the sidebar
        azure_api_key = st.text_input(
            get_text("azure_api_key_label", st.session_state.language),
            value=st.session_state.get('azure_api_key', ''),
            type="password",
            help=get_text("azure_api_key_help", st.session_state.language),
        )
        if azure_api_key:
            st.session_state['azure_api_key'] = azure_api_key

        # Add Azure OpenAI endpoint input field to the sidebar
        azure_api_endpoint = st.text_input(
            get_text("azure_endpoint_label", st.session_state.language),
            value=st.session_state.get('azure_api_endpoint', ''),
            help="Example endpoint: https://YOUR_RESOURCE_NAME.openai.azure.com/",
        )
        if azure_api_endpoint:
            st.session_state['azure_api_endpoint'] = azure_api_endpoint

        # Add Azure OpenAI deployment name input field to the sidebar
        azure_deployment_name = st.text_input(
            get_text("azure_deployment_label", st.session_state.language),
            value=st.session_state.get('azure_deployment_name', ''),
        )
        if azure_deployment_name:
            st.session_state['azure_deployment_name'] = azure_deployment_name
        
        st.info(get_text("azure_info", st.session_state.language))

        azure_api_version = '2023-12-01-preview' # Update this as needed

        st.write(get_text("azure_version", st.session_state.language).format(azure_api_version))

    if model_provider == "Google AI API":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("Google AI") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add Google API key input field to the sidebar
        google_api_key = st.text_input(
            get_text("google_api_key_label", st.session_state.language),
            value=st.session_state.get('google_api_key', ''),
            type="password",
            help=get_text("google_api_key_help", st.session_state.language),
        )
        if google_api_key:
            st.session_state['google_api_key'] = google_api_key

        # Add model selection input field to the sidebar
        google_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            ["gemini-2.5-pro-preview-05-06", "gemini-2.5-flash-preview-05-20", "gemini-2.0-flash", "gemini-2.0-flash-lite"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("google_model_help", st.session_state.language)
        )

    if model_provider == "Mistral API":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("Mistral") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add Mistral API key input field to the sidebar
        mistral_api_key = st.text_input(
            get_text("mistral_api_key_label", st.session_state.language),
            value=st.session_state.get('mistral_api_key', ''),
            type="password",
            help=get_text("mistral_api_key_help", st.session_state.language),
        )
        if mistral_api_key:
            st.session_state['mistral_api_key'] = mistral_api_key

        # Add model selection input field to the sidebar
        mistral_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            ["mistral-large-latest", "mistral-small-latest"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("mistral_model_help", st.session_state.language)
        )

    if model_provider == "Ollama":
        st.markdown(
        get_text("step_enter_endpoint", st.session_state.language).format("Ollama") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add Ollama endpoint configuration field
        ollama_endpoint = st.text_input(
            get_text("ollama_endpoint_label", st.session_state.language),
            value=st.session_state.get('ollama_endpoint', 'http://localhost:11434'),
            help=get_text("ollama_endpoint_help", st.session_state.language),
        )
        if ollama_endpoint:
            # Basic URL validation
            if not ollama_endpoint.startswith(('http://', 'https://')):
                st.error("Endpoint URL must start with http:// or https://")
            else:
                st.session_state['ollama_endpoint'] = ollama_endpoint
                # Fetch available models from Ollama
                available_models = get_ollama_models(ollama_endpoint)

        # Add model selection input field
        selected_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            available_models if ollama_endpoint and ollama_endpoint.startswith(('http://', 'https://')) else ["local-model"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("ollama_model_help", st.session_state.language)
        )

    if model_provider == "LM Studio Server":
        st.markdown(
        get_text("step_enter_endpoint", st.session_state.language).format("LM Studio Server") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add LM Studio Server endpoint configuration field
        lm_studio_endpoint = st.text_input(
            get_text("lm_studio_endpoint_label", st.session_state.language),
            value=st.session_state.get('lm_studio_endpoint', 'http://localhost:1234'),
            help=get_text("lm_studio_endpoint_help", st.session_state.language),
        )
        if lm_studio_endpoint:
            # Basic URL validation
            if not lm_studio_endpoint.startswith(('http://', 'https://')):
                st.error("Endpoint URL must start with http:// or https://")
            else:
                st.session_state['lm_studio_endpoint'] = lm_studio_endpoint
                # Fetch available models from LM Studio Server
                available_models = get_lm_studio_models(lm_studio_endpoint)

        # Add model selection input field
        selected_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            available_models if lm_studio_endpoint and lm_studio_endpoint.startswith(('http://', 'https://')) else ["local-model"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("lm_studio_model_help", st.session_state.language)
        )

    if model_provider == "Groq API":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("Groq") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add Groq API key input field to the sidebar
        groq_api_key = st.text_input(
            get_text("groq_api_key_label", st.session_state.language),
            value=st.session_state.get('groq_api_key', ''),
            type="password",
            help=get_text("groq_api_key_help", st.session_state.language),
        )
        if groq_api_key:
            st.session_state['groq_api_key'] = groq_api_key

        # Add model selection input field to the sidebar
        groq_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            [
                "deepseek-r1-distill-llama-70b",
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "gemma-9b-it"
            ],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("groq_model_help", st.session_state.language)
        )

    if model_provider == "GLM API":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("GLM") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add GLM API key input field to the sidebar
        glm_api_key = st.text_input(
            get_text("glm_api_key_label", st.session_state.language),
            value=st.session_state.get('glm_api_key', ''),
            type="password",
            help=get_text("glm_api_key_help", st.session_state.language),
        )
        if glm_api_key:
            st.session_state['glm_api_key'] = glm_api_key

        # Add model selection input field to the sidebar
        glm_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            ["glm-4.5", "glm-4.5-air"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("glm_model_help", st.session_state.language)
        )

    if model_provider == "eCloud":
        st.markdown(
        get_text("step_enter_api_key", st.session_state.language).format("eCloud") + "\n" +
        get_text("step_provide_details", st.session_state.language) + "\n" +
        get_text("step_generate_output", st.session_state.language)
    )
        # Add eCloud API key input field to the sidebar
        ecloud_api_key = st.text_input(
            get_text("ecloud_api_key_label", st.session_state.language),
            value=st.session_state.get('ecloud_api_key', ''),
            type="password",
            help=get_text("ecloud_api_key_help", st.session_state.language),
        )
        if ecloud_api_key:
            st.session_state['ecloud_api_key'] = ecloud_api_key

        # Add model selection input field to the sidebar
        ecloud_model = st.selectbox(
            get_text("model_selection_label", st.session_state.language),
            ["deepseek-v3"],
            key="selected_model",
            on_change=on_model_selection_change,
            help=get_text("ecloud_model_help", st.session_state.language)
        )

    # Add GitHub API key input field to the sidebar
    github_api_key = st.text_input(
        get_text("github_api_key_label", st.session_state.language),
        value=st.session_state.get('github_api_key', ''),
        type="password",
        help=get_text("github_api_key_help", st.session_state.language),
    )

    # Store the GitHub API key in session state
    if github_api_key:
        st.session_state['github_api_key'] = github_api_key

    # Add Gerrit authentication input fields to the sidebar
    st.markdown("### Gerrit Authentication")

    gerrit_username = st.text_input(
        get_text("gerrit_username_label", st.session_state.language),
        value=st.session_state.get('gerrit_username', ''),
        help=get_text("gerrit_username_help", st.session_state.language),
    )

    gerrit_password = st.text_input(
        get_text("gerrit_password_label", st.session_state.language),
        value=st.session_state.get('gerrit_password', ''),
        type="password",
        help=get_text("gerrit_password_help", st.session_state.language),
    )

    # Store Gerrit credentials in session state
    if gerrit_username:
        st.session_state['gerrit_username'] = gerrit_username
    if gerrit_password:
        st.session_state['gerrit_password'] = gerrit_password

    # Add Advanced Settings section with token limit configuration
    with st.expander(get_text("advanced_settings", st.session_state.language)):
    
        # Get the current model provider and selected model
        current_provider = st.session_state.get('model_provider', 'OpenAI API')
        current_model = st.session_state.get('selected_model', '')
        
        # Create the key for lookup
        model_key = f"{current_provider}:{current_model}"
        
        # Get the max token limit for the current model
        max_token_limit = 128000  # Default max
        default_token_limit = 64000  # Default value
        
        if model_key in model_token_limits:
            max_token_limit = model_token_limits[model_key]["max"]
            default_token_limit = model_token_limits[model_key]["default"]
        else:
            # Try provider default
            provider_key = f"{current_provider}:default"
            if provider_key in model_token_limits:
                max_token_limit = model_token_limits[provider_key]["max"]
                default_token_limit = model_token_limits[provider_key]["default"]
        
        # Store the current model and provider to detect changes
        current_model_key = st.session_state.get('current_model_key', '')
        
        # If token_limit is not set or the model/provider has changed, update the token limit
        if 'token_limit' not in st.session_state or current_model_key != model_key:
            st.session_state.token_limit = default_token_limit
            st.session_state.current_model_key = model_key
        
        # Add token limit slider with fixed minimum and dynamic maximum
        token_limit = st.slider(
            get_text("github_token_limit_label", st.session_state.language),
            min_value=4000,  # Fixed minimum as requested
            max_value=max_token_limit,
            value=st.session_state.token_limit,  # Use the current value from session state
            step=1000,
            help=get_text("github_token_limit_help", st.session_state.language)
        )
        
        # Store the GitHub token limit in session state
        st.session_state['token_limit'] = token_limit

        # Add Gerrit token limit configuration
        # Get the max token limit for Gerrit (can use same limits as GitHub)
        gerrit_max_token_limit = max_token_limit
        gerrit_default_token_limit = default_token_limit

        # If gerrit_token_limit is not set, update the token limit
        if 'gerrit_token_limit' not in st.session_state:
            st.session_state.gerrit_token_limit = gerrit_default_token_limit

        # Add Gerrit token limit slider
        gerrit_token_limit = st.slider(
            get_text("gerrit_token_limit_label", st.session_state.language),
            min_value=4000,
            max_value=gerrit_max_token_limit,
            value=st.session_state.gerrit_token_limit,
            step=1000,
            help=get_text("gerrit_token_limit_help", st.session_state.language)
        )

        # Store the Gerrit token limit in session state
        st.session_state['gerrit_token_limit'] = gerrit_token_limit

    st.markdown("---")

    # Add "About" section to the sidebar
    st.header(get_text("about_header", st.session_state.language))
    
    st.markdown(
        get_text("about_welcome", st.session_state.language)
    )
    st.markdown(
        get_text("about_description", st.session_state.language)
    )
    st.markdown(get_text("about_created_by", st.session_state.language))
    
    st.markdown("""---""")


# Add "Example Application Description" section to the sidebar
st.sidebar.header(get_text("example_app_header", st.session_state.language))

with st.sidebar:
    st.markdown(get_text("example_app_description", st.session_state.language))
    st.markdown(
        "> A web application that allows users to create, store, and share personal notes. The application is built using the React frontend framework and a Node.js backend with a MongoDB database. Users can sign up for an account and log in using OAuth2 with Google or Facebook. The notes are encrypted at rest and are only accessible by the user who created them. The application also supports real-time collaboration on notes with other users."
    )
    st.markdown("""---""")

# Add "FAQs" section to the sidebar
st.sidebar.header(get_text("faqs_header", st.session_state.language))

with st.sidebar:
    st.markdown(get_text("faqs_stride_question", st.session_state.language))
    st.markdown(get_text("faqs_stride_answer", st.session_state.language))
    st.markdown(get_text("faqs_how_works_question", st.session_state.language))
    st.markdown(get_text("faqs_how_works_answer", st.session_state.language))
    st.markdown(get_text("faqs_storage_question", st.session_state.language))
    st.markdown(get_text("faqs_storage_answer", st.session_state.language))
    st.markdown(get_text("faqs_slow_question", st.session_state.language))
    st.markdown(get_text("faqs_slow_answer", st.session_state.language))
    st.markdown(get_text("faqs_accuracy_question", st.session_state.language))
    st.markdown(get_text("faqs_accuracy_answer", st.session_state.language))
    st.markdown(get_text("faqs_improve_question", st.session_state.language))
    st.markdown(get_text("faqs_improve_answer", st.session_state.language))


# ------------------ Main App UI ------------------ #

# Simple header
st.markdown("""
<div style="
    padding: 1rem;
    margin-bottom: 1rem;
    text-align: center;
">
    <h1 style="
        color: #c9d1d9;
        margin: 0;
        font-size: 2rem;
        font-weight: 600;
    ">
        🛡️ STRIDE GPT
    </h1>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    get_text("threat_model_header", st.session_state.language),
    get_text("attack_tree_header", st.session_state.language),
    get_text("mitigations_header", st.session_state.language),
    get_text("dread_header", st.session_state.language),
    get_text("test_cases_header", st.session_state.language)
])

with tab1:
    st.markdown(f"""
    <div class="enhanced-card">
        <h2>{get_text("threat_model_header", st.session_state.language)}</h2>
        <p>{get_text("threat_model_description", st.session_state.language)}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""---""")
    
    # Two column layout for the main app content
    col1, col2 = st.columns([1, 1])

    # Initialize app_input in the session state if it doesn't exist
    if 'app_input' not in st.session_state:
        st.session_state['app_input'] = ''

    # Display image uploader for supported multimodal models
    with col1:
        supports_image = False
        # Get selected_model from session state
        selected_model = st.session_state.get('selected_model', '')
        
        if model_provider == "OpenAI API" and (selected_model.startswith("gpt-4") or selected_model == "o4-mini"):
            supports_image = True
        elif model_provider == "Azure OpenAI Service":
            supports_image = True
        elif model_provider == "Google AI API":
            supports_image = True
        elif model_provider == "Anthropic API" and selected_model.startswith("claude-3"):
            supports_image = True
        elif model_provider == "GLM API" and selected_model == "glm-4v-plus":
            supports_image = True

        if supports_image:
            uploaded_file = st.file_uploader(get_text("upload_architecture_diagram", st.session_state.language), type=["jpg", "jpeg", "png"])

            if uploaded_file is not None:
                def encode_image(uploaded_file):
                    return base64.b64encode(uploaded_file.read()).decode('utf-8')

                base64_image = encode_image(uploaded_file)
                image_analysis_prompt = create_image_analysis_prompt()
                
                # Determine media type from file extension
                file_type = uploaded_file.type
                if file_type == "image/png":
                    media_type = "image/png"
                elif file_type in ["image/jpeg", "image/jpg"]:
                    media_type = "image/jpeg"
                else:
                    media_type = "image/jpeg"  # Default fallback

                try:
                    if model_provider == "OpenAI API":
                        if not openai_api_key:
                            st.error(get_text("please_enter_api_key", st.session_state.language).format("OpenAI"))
                            raise ValueError
                        image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
                    elif model_provider == "Azure OpenAI Service":
                        if not azure_api_key or not azure_api_endpoint or not azure_deployment_name:
                            st.error(get_text("please_enter_api_key", st.session_state.language).format("Azure OpenAI"))
                            raise ValueError
                        azure_api_version = '2023-12-01-preview'
                        image_analysis_output = get_image_analysis_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, image_analysis_prompt, base64_image)
                    elif model_provider == "Google AI API":
                        if not google_api_key:
                            st.error(get_text("please_enter_api_key", st.session_state.language).format("Google AI"))
                            raise ValueError
                        image_analysis_output = get_image_analysis_google(google_api_key, selected_model, image_analysis_prompt, base64_image)
                    elif model_provider == "Anthropic API":
                        if not anthropic_api_key:
                            st.error(get_text("please_enter_api_key", st.session_state.language).format("Anthropic"))
                            raise ValueError
                        image_analysis_output = get_image_analysis_anthropic(anthropic_api_key, selected_model, image_analysis_prompt, base64_image, media_type)
                    elif model_provider == "GLM API":
                        if not glm_api_key:
                            st.error(get_text("please_enter_api_key", st.session_state.language).format("GLM"))
                            raise ValueError
                        image_analysis_output = get_image_analysis_glm(glm_api_key, selected_model, image_analysis_prompt, base64_image, media_type)
                    else:
                        image_analysis_output = None

                    if image_analysis_output and 'choices' in image_analysis_output and image_analysis_output['choices'][0]['message']['content']:
                        image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                        st.session_state.image_analysis_content = image_analysis_content
                        st.session_state['app_input'] = image_analysis_content
                    else:
                        st.error(get_text("failed_to_analyze", st.session_state.language))
                except Exception as e:
                    st.error(get_text("error_analyzing_image", st.session_state.language).format(str(e)))

        # Use the get_input() function to get the application description and GitHub URL
        app_input = get_input()
        # Update session state only if the text area content has changed
        if app_input != st.session_state['app_input']:
            st.session_state['app_input'] = app_input

    # Ensure app_input is always up to date in the session state
    app_input = st.session_state['app_input']



        # Create input fields for additional details
    with col2:
            app_type = st.selectbox(
                label=get_text("app_type_label", st.session_state.language),
                options=[
                    get_text("app_type_web", st.session_state.language),
                    get_text("app_type_mobile", st.session_state.language),
                    get_text("app_type_desktop", st.session_state.language),
                    get_text("app_type_cloud", st.session_state.language),
                    get_text("app_type_iot", st.session_state.language),
                    get_text("app_type_other", st.session_state.language),
                ],
                key="app_type",
                help=get_text("app_type_help", st.session_state.language),
            )

            sensitive_data = st.selectbox(
                label=get_text("sensitive_data_label", st.session_state.language),
                options=[
                    get_text("classification_top_secret", st.session_state.language),
                    get_text("classification_secret", st.session_state.language),
                    get_text("classification_confidential", st.session_state.language),
                    get_text("classification_restricted", st.session_state.language),
                    get_text("classification_unclassified", st.session_state.language),
                    get_text("auth_none", st.session_state.language),
                ],
                key="sensitive_data",
                help=get_text("sensitive_data_help", st.session_state.language),
            )

        # Create input fields for internet_facing and authentication
            internet_facing = st.selectbox(
                label=get_text("internet_facing_label", st.session_state.language),
                options=[get_text("auth_yes", st.session_state.language), get_text("auth_no", st.session_state.language)],
                key="internet_facing",
                help=get_text("internet_facing_help", st.session_state.language),
            )

            authentication = st.multiselect(
                get_text("auth_label", st.session_state.language),
                ["SSO", "MFA", "OAUTH2", "Basic", get_text("auth_none", st.session_state.language)],
                key="authentication",
                help=get_text("auth_help", st.session_state.language),
            )



    # ------------------ Threat Model Generation ------------------ #

    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label=get_text("analyze_button", st.session_state.language))

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and st.session_state.get('app_input'):
        app_input = st.session_state['app_input']  # Retrieve from session state
        # Generate the prompt using the create_prompt function
        threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input, st.session_state.language)

        # Clear thinking content when switching models or starting a new operation
        if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
            st.session_state.pop('last_thinking_content', None)

        # Show a spinner while generating the threat model
        with st.spinner(get_text("analysing_threats", st.session_state.language)):
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if model_provider == "Azure OpenAI Service":
                        model_output = get_threat_model_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, threat_model_prompt)
                    elif model_provider == "OpenAI API":
                        model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                    elif model_provider == "Google AI API":
                        model_output = get_threat_model_google(google_api_key, google_model, threat_model_prompt)
                    elif model_provider == "Mistral API":
                        model_output = get_threat_model_mistral(mistral_api_key, mistral_model, threat_model_prompt)
                    elif model_provider == "Ollama":
                        model_output = get_threat_model_ollama(st.session_state['ollama_endpoint'], selected_model, threat_model_prompt)
                    elif model_provider == "Anthropic API":
                        model_output = get_threat_model_anthropic(anthropic_api_key, anthropic_model, threat_model_prompt)
                        # Check if we got a fallback response
                        if model_output.get("threat_model") and len(model_output["threat_model"]) == 1 and model_output["threat_model"][0].get("Threat Type") == "Error":
                            st.warning("⚠️ " + get_text("threat_model_generation_issue", st.session_state.language))
                            st.markdown("1. " + get_text("retry_generation", st.session_state.language))
                            st.markdown("2. " + get_text("check_logs", st.session_state.language))
                            st.markdown("3. " + get_text("use_different_model", st.session_state.language))
                    elif model_provider == "LM Studio Server":
                        model_output = get_threat_model_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, threat_model_prompt)
                    elif model_provider == "Groq API":
                        model_output = get_threat_model_groq(groq_api_key, groq_model, threat_model_prompt)
                    elif model_provider == "GLM API":
                        model_output = get_threat_model_glm(glm_api_key, glm_model, threat_model_prompt)
                    elif model_provider == "eCloud":
                        model_output = get_threat_model_ecloud(ecloud_api_key, ecloud_model, threat_model_prompt)

                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model to the session state for later use in mitigations
                    st.session_state['threat_model'] = threat_model
                    break  # Exit the loop if successful
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        st.error(get_text("error_generating_threat_model", st.session_state.language).format(max_retries, e))
                        threat_model = []
                        improvement_suggestions = []
                    else:
                        st.warning(get_text("retrying_threat_model", st.session_state.language).format(retry_count+1, max_retries))

        # Convert the threat model JSON to Markdown
        markdown_output = json_to_markdown(threat_model, improvement_suggestions, st.session_state.language)

        # Display thinking content in an expander if available
        if ('last_thinking_content' in st.session_state and 
            st.session_state['last_thinking_content'] and 
            ((model_provider == "Anthropic API" and "thinking" in anthropic_model.lower()) or
             (model_provider == "Google AI API" and "gemini-2.5" in google_model.lower()))):
            thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
            with st.expander(get_text("view_thinking_process", st.session_state.language).format(thinking_model)):
                st.markdown(st.session_state['last_thinking_content'])

        # Display the threat model in Markdown
        st.markdown(markdown_output)
        
        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label=get_text("download_threat_model", st.session_state.language),
            data=markdown_output,
            file_name="threat_model.md",
            mime="text/markdown",
        )
        
# If the submit button is clicked and the user has not provided an application description
if threat_model_submit_button and not st.session_state.get('app_input'):
    st.error(get_text("please_enter_app_details", st.session_state.language))



# ------------------ Attack Tree Generation ------------------ #

with tab2:
    st.markdown(f"""
    <div class="enhanced-card">
        <h2>{get_text("attack_tree_header", st.session_state.language)}</h2>
        <p>{get_text("attack_tree_description", st.session_state.language)}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""---""")
    if model_provider == "Mistral API" and mistral_model == "mistral-small-latest":
        st.warning(get_text("mistral_small_warning", st.session_state.language))
    else:
        if model_provider in ["Ollama", "LM Studio Server"]:
            st.warning(get_text("local_llm_warning", st.session_state.language))
        
        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label=get_text("generate_attack_tree", st.session_state.language))
        
        # If the Generate Attack Tree button is clicked and the user has provided an application description
        if attack_tree_submit_button and st.session_state.get('app_input'):
            app_input = st.session_state.get('app_input')
            # Generate the prompt using the create_attack_tree_prompt function
            attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input, st.session_state.language)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating the attack tree
            with st.spinner(get_text("generating_attack_tree", st.session_state.language)):
                try:
                    # Call the relevant get_attack_tree function with the generated prompt
                    if model_provider == "Azure OpenAI Service":
                        mermaid_code = get_attack_tree_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "OpenAI API":
                        mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "Google AI API":
                        mermaid_code = get_attack_tree_google(google_api_key, google_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "Mistral API":
                        mermaid_code = get_attack_tree_mistral(mistral_api_key, mistral_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "Ollama":
                        mermaid_code = get_attack_tree_ollama(st.session_state['ollama_endpoint'], selected_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "Anthropic API":
                        mermaid_code = get_attack_tree_anthropic(anthropic_api_key, anthropic_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "LM Studio Server":
                        mermaid_code = get_attack_tree_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "Groq API":
                        mermaid_code = get_attack_tree_groq(groq_api_key, groq_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "GLM API":
                        mermaid_code = get_attack_tree_glm(glm_api_key, glm_model, attack_tree_prompt, st.session_state.language)
                    elif model_provider == "eCloud":
                        mermaid_code = get_attack_tree_ecloud(ecloud_api_key, ecloud_model, attack_tree_prompt, st.session_state.language)

                    # Display thinking content in an expander if available
                    if ('last_thinking_content' in st.session_state and 
                        st.session_state['last_thinking_content'] and 
                        ((model_provider == "Anthropic API" and "thinking" in anthropic_model.lower()) or
                         (model_provider == "Google AI API" and "gemini-2.5" in google_model.lower()))):
                        thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                        with st.expander(get_text("view_thinking_process", st.session_state.language).format(thinking_model)):
                            st.markdown(st.session_state['last_thinking_content'])

                    # Display the generated attack tree code
                    st.write(get_text("attack_tree_code", st.session_state.language))
                    st.code(mermaid_code)

                    # Visualise the attack tree using the Mermaid custom component
                    st.write(get_text("attack_tree_preview", st.session_state.language))
                    mermaid(mermaid_code)
                    
                    col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                    
                    with col1:
                        # Add a button to allow the user to download the Mermaid code
                        st.download_button(
                            label=get_text("download_diagram_code", st.session_state.language),
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                            help="Download the Mermaid code for the attack tree diagram."
                        )

                    with col2:
                        # Add a button to allow the user to open the Mermaid Live editor
                        mermaid_live_button = st.link_button(get_text("open_mermaid_live", st.session_state.language), "https://mermaid.live")

                    with col3:
                        # Blank placeholder
                        st.write("")

                    with col4:
                        # Blank placeholder
                        st.write("")

                    with col5:
                        # Blank placeholder
                        st.write("")
                    
                except Exception as e:
                    st.error(get_text("error_generating_attack_tree", st.session_state.language).format(e))


# ------------------ Mitigations Generation ------------------ #

with tab3:
    st.markdown(f"""
    <div class="enhanced-card">
        <h2>{get_text("mitigations_header", st.session_state.language)}</h2>
        <p>{get_text("mitigations_description", st.session_state.language)}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""---""")
    
    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label=get_text("suggest_mitigations", st.session_state.language))

    # If the Suggest Mitigations button is clicked and the user has identified threats
    if mitigations_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [], st.session_state.language)
            # Generate the prompt using the create_mitigations_prompt function
            mitigations_prompt = create_mitigations_prompt(threats_markdown, st.session_state.language)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while suggesting mitigations
            with st.spinner(get_text("suggesting_mitigations", st.session_state.language)):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_mitigations function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            mitigations_markdown = get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, mitigations_prompt, st.session_state.language)
                        elif model_provider == "OpenAI API":
                            mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "Google AI API":
                            mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "Mistral API":
                            mitigations_markdown = get_mitigations_mistral(mistral_api_key, mistral_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "Ollama":
                            mitigations_markdown = get_mitigations_ollama(st.session_state['ollama_endpoint'], selected_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "Anthropic API":
                            mitigations_markdown = get_mitigations_anthropic(anthropic_api_key, anthropic_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "LM Studio Server":
                            mitigations_markdown = get_mitigations_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "Groq API":
                            mitigations_markdown = get_mitigations_groq(groq_api_key, groq_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "GLM API":
                            mitigations_markdown = get_mitigations_glm(glm_api_key, glm_model, mitigations_prompt, st.session_state.language)
                        elif model_provider == "eCloud":
                            mitigations_markdown = get_mitigations_ecloud(ecloud_api_key, ecloud_model, mitigations_prompt, st.session_state.language)

                        # Display thinking content in an expander if available and using a model with thinking capabilities
                        if ('last_thinking_content' in st.session_state and 
                            st.session_state['last_thinking_content'] and 
                            ((model_provider == "Anthropic API" and "thinking" in anthropic_model.lower()) or
                             (model_provider == "Google AI API" and "gemini-2.5" in google_model.lower()))):
                            thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                            with st.expander(get_text("view_thinking_process", st.session_state.language).format(thinking_model)):
                                st.markdown(st.session_state['last_thinking_content'])

                        # Display the suggested mitigations in Markdown
                        st.markdown(mitigations_markdown)
                        
                        st.markdown("")
                        
                        # Add a button to allow the user to download the mitigations as a Markdown file
                        st.download_button(
                            label=get_text("download_mitigations", st.session_state.language),
                            data=mitigations_markdown,
                            file_name="mitigations.md",
                            mime="text/markdown",
                        )
                        
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(get_text("error_generating_mitigations", st.session_state.language).format(max_retries, e))
                            mitigations_markdown = ""
                        else:
                            st.warning(get_text("retrying_mitigations", st.session_state.language).format(retry_count+1, max_retries))
            
            st.markdown("")
        else:
            st.error(get_text("generate_threat_model_first", st.session_state.language).format(get_text("suggesting_mitigations", st.session_state.language)))

# ------------------ DREAD Risk Assessment Generation ------------------ #
with tab4:
    st.markdown(f"""
    <div class="enhanced-card">
        <h2>{get_text("dread_header", st.session_state.language)}</h2>
        <p>{get_text("dread_description", st.session_state.language)}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""---""")
    
    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label=get_text("generate_dread", st.session_state.language))
    # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
    if dread_assessment_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [], st.session_state.language)
            # Generate the prompt using the create_dread_assessment_prompt function
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown, st.session_state.language)
            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating DREAD Risk Assessment
            with st.spinner(get_text("generating_dread", st.session_state.language)):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_dread_assessment function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            dread_assessment = get_dread_assessment_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "OpenAI API":
                            dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "Google AI API":
                            dread_assessment = get_dread_assessment_google(google_api_key, google_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "Mistral API":
                            dread_assessment = get_dread_assessment_mistral(mistral_api_key, mistral_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "Ollama":
                            dread_assessment = get_dread_assessment_ollama(st.session_state['ollama_endpoint'], selected_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "Anthropic API":
                            dread_assessment = get_dread_assessment_anthropic(anthropic_api_key, anthropic_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "LM Studio Server":
                            dread_assessment = get_dread_assessment_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "Groq API":
                            dread_assessment = get_dread_assessment_groq(groq_api_key, groq_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "GLM API":
                            dread_assessment = get_dread_assessment_glm(glm_api_key, glm_model, dread_assessment_prompt, st.session_state.language)
                        elif model_provider == "eCloud":
                            dread_assessment = get_dread_assessment_ecloud(ecloud_api_key, ecloud_model, dread_assessment_prompt, st.session_state.language)
                        
                        # Save the DREAD assessment to the session state for later use in test cases
                        st.session_state['dread_assessment'] = dread_assessment
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(get_text("error_generating_dread", st.session_state.language).format(max_retries, e))
                            dread_assessment = {"Risk Assessment": []}
                            # Add debug information
                            st.error(get_text("debug_no_threats", st.session_state.language))
                        else:
                            st.warning(get_text("retrying_dread", st.session_state.language).format(retry_count+1, max_retries))
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment, st.session_state.language)
            
            # Add debug information about the assessment
            if not dread_assessment.get("Risk Assessment"):
                st.warning(get_text("debug_empty_dread", st.session_state.language))
            
            # Display thinking content in an expander if available and using a model with thinking capabilities
            if ('last_thinking_content' in st.session_state and 
                st.session_state['last_thinking_content'] and 
                ((model_provider == "Anthropic API" and "thinking" in anthropic_model.lower()) or
                 (model_provider == "Google AI API" and "gemini-2.5" in google_model.lower()))):
                thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                with st.expander(get_text("view_thinking_process", st.session_state.language).format(thinking_model)):
                    st.markdown(st.session_state['last_thinking_content'])
                    
            # Display the DREAD assessment with a header
            st.markdown("## " + get_text("dread_assessment_header", st.session_state.language))
            st.markdown(get_text("dread_description", st.session_state.language))
            
            # Display the DREAD assessment in Markdown format
            st.markdown(dread_assessment_markdown, unsafe_allow_html=False)
            
            # Add a button to allow the user to download the DREAD assessment as a Markdown file
            st.download_button(
                label=get_text("download_dread", st.session_state.language),
                data=dread_assessment_markdown,
                file_name="dread_assessment.md",
                mime="text/markdown",
            )
        else:
            st.error(get_text("generate_threat_model_first", st.session_state.language).format(get_text("requesting_dread", st.session_state.language)))


# ------------------ Test Cases Generation ------------------ #

with tab5:
    st.markdown(f"""
    <div class="enhanced-card">
        <h2>{get_text("test_cases_header", st.session_state.language)}</h2>
        <p>{get_text("test_cases_description", st.session_state.language)}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""---""")
                
    # Create a submit button for Test Cases
    test_cases_submit_button = st.button(label=get_text("generate_test_cases", st.session_state.language))

    # If the Generate Test Cases button is clicked and the user has identified threats
    if test_cases_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [], st.session_state.language)
            # Generate the prompt using the create_test_cases_prompt function
            test_cases_prompt = create_test_cases_prompt(threats_markdown, st.session_state.language)

            # Clear thinking content when switching models or starting a new operation
            if model_provider != "Anthropic API" or "thinking" not in anthropic_model.lower():
                st.session_state.pop('last_thinking_content', None)

            # Show a spinner while generating test cases
            with st.spinner(get_text("generating_test_cases", st.session_state.language)):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call to the relevant get_test_cases function with the generated prompt
                        if model_provider == "Azure OpenAI Service":
                            test_cases_markdown = get_test_cases_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, test_cases_prompt, st.session_state.language)
                        elif model_provider == "OpenAI API":
                            test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "Google AI API":
                            test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "Mistral API":
                            test_cases_markdown = get_test_cases_mistral(mistral_api_key, mistral_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "Ollama":
                            test_cases_markdown = get_test_cases_ollama(st.session_state['ollama_endpoint'], selected_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "Anthropic API":
                            test_cases_markdown = get_test_cases_anthropic(anthropic_api_key, anthropic_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "LM Studio Server":
                            test_cases_markdown = get_test_cases_lm_studio(st.session_state['lm_studio_endpoint'], selected_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "Groq API":
                            test_cases_markdown = get_test_cases_groq(groq_api_key, groq_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "GLM API":
                            test_cases_markdown = get_test_cases_glm(glm_api_key, glm_model, test_cases_prompt, st.session_state.language)
                        elif model_provider == "eCloud":
                            test_cases_markdown = get_test_cases_ecloud(ecloud_api_key, ecloud_model, test_cases_prompt, st.session_state.language)

                        # Display thinking content in an expander if available and using a model with thinking capabilities
                        if ('last_thinking_content' in st.session_state and 
                            st.session_state['last_thinking_content'] and 
                            ((model_provider == "Anthropic API" and "thinking" in anthropic_model.lower()) or
                             (model_provider == "Google AI API" and "gemini-2.5" in google_model.lower()))):
                            thinking_model = "Claude" if model_provider == "Anthropic API" else "Gemini"
                            with st.expander(get_text("view_thinking_process", st.session_state.language).format(thinking_model)):
                                st.markdown(st.session_state['last_thinking_content'])

                        # Display the suggested mitigations in Markdown
                        st.markdown(test_cases_markdown)
                        
                        st.markdown("")

                        # Add a button to allow the user to download the test cases as a Markdown file
                        st.download_button(
                            label=get_text("download_test_cases", st.session_state.language),
                            data=test_cases_markdown,
                            file_name="test_cases.md",
                            mime="text/markdown",
                        )
                        
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(get_text("error_generating_test_cases", st.session_state.language).format(max_retries, e))
                            test_cases_markdown = ""
                        else:
                            st.warning(get_text("retrying_test_cases", st.session_state.language).format(retry_count+1, max_retries))
            
            st.markdown("")

        else:
            st.error(get_text("generate_threat_model_first", st.session_state.language).format(get_text("requesting_test_cases", st.session_state.language)))